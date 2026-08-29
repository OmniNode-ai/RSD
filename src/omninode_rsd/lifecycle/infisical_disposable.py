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
_DOCKER_DAEMON_ID: Final = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_OWNER_IDENTITY: Final = r"^[A-Za-z0-9][A-Za-z0-9@._+-]{0,254}$"
_TIMESTAMP: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]{1,6})?Z\Z"
)
_ENGINE_FINGERPRINT_DOMAIN: Final = b"omninode-rsd.docker-engine-projection.sha256.v1\x00"
_VOLUME_INSTANCE_FINGERPRINT_DOMAIN: Final = (
    b"omninode-rsd.docker-named-volume-instance.sha256.v1\x00"
)
_UNIX_SOCKET_IDENTITY_DOMAIN: Final = b"omninode-rsd.docker-unix-socket-identity.sha256.v1\x00"
_CREATE_TEMPLATE_DOMAIN: Final = b"omninode-rsd.docker-create-template.sha256.v1\x00"
_WRAPPER_ARTIFACT_DOMAIN: Final = b"omninode-rsd.container-wrapper-artifact.sha256.v1\x00"
_WRAPPER_MANIFEST_DOMAIN: Final = b"omninode-rsd.container-wrapper-manifest.sha256.v1\x00"
_LOCAL_ATTACH_PROTOCOL_DOMAIN: Final = b"omninode-rsd.container-attach-protocol.sha256.v1\x00"
_TARGET_DELIVERY_MAP_DOMAIN: Final = b"omninode-rsd.target-delivery-map.sha256.v1\x00"
_URI_GRAMMAR_DOMAIN: Final = b"omninode-rsd.runtime-uri-grammar.sha256.v1\x00"
_VALKEY_SCHEME: Final = "redis:"
_VALKEY_FIXED_PORT: Final = 6379
_LOCAL_ATTACH_REQUEST_DOMAIN: Final = b"omninode-rsd.container-attach-request.sha256.v1\x00"
_LOCAL_ATTACH_ACK_DOMAIN: Final = b"omninode-rsd.container-attach-ack.sha256.v1\x00"
_LOCAL_ATTACH_CHUNK_DESCRIPTORS_DOMAIN: Final = (
    b"omninode-rsd.container-attach-chunk-descriptors.sha256.v1\x00"
)
_LOCAL_ATTACH_RECEIPT_DOMAIN: Final = b"omninode-rsd.container-attach-receipt.sha256.v1\x00"
_OBSERVED_RESTORE_DATABASE_ATTESTATION_DOMAIN: Final = (
    b"omninode-rsd.observed-restore-database-attestation.sha256.v1\x00"
)
_ALLOCATION_EXECUTOR_RECEIPT_DOMAIN: Final = (
    b"omninode-rsd.allocation-executor-receipt.ed25519.v1\x00"
)
_MATERIALIZATION_EXECUTOR_RECEIPT_DOMAIN: Final = (
    b"omninode-rsd.materialization-executor-receipt.ed25519.v1\x00"
)
_START_RUNTIME_EXECUTOR_RECEIPT_DOMAIN: Final = (
    b"omninode-rsd.start-runtime-executor-receipt.ed25519.v2\x00"
)
_OCI_IMAGE_RESOLUTION_ATTESTATION_DOMAIN: Final = (
    b"omninode-rsd.oci-image-resolution-attestation.ed25519.v1\x00"
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


def _domain_sha256(domain: bytes, value: BaseModel) -> str:
    """Hash one canonical, non-secret projection under an explicit domain."""

    if type(domain) is not bytes or not domain.endswith(b"\x00"):
        raise ValueError("digest domain is invalid")
    return _digest(domain + _canonical_model_bytes(value))


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
            # Docker's container ID is the workload identity.  Docker does
            # not expose a second native ``workload_id`` field, so accepting
            # one here would create an unverifiable identity claim.
            StableIdentifierV1(kind=StableIdentifierKind.WORKLOAD, value=self.container_id),
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
    volume_instance_fingerprint_sha256: str = Field(pattern=_SHA256)
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    workload_name: str = Field(pattern=_IDENTIFIER)
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
            StableIdentifierV1(
                kind=StableIdentifierKind.VOLUME,
                value=self.volume_instance_fingerprint_sha256,
            ),
            StableIdentifierV1(
                kind=StableIdentifierKind.VALKEY_NAMESPACE_WORKLOAD,
                value=f"{self.logical_namespace}/{self.container_id}",
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
        if len({item.workload_name for item in components}) != 4:
            raise ValueError("all component workload names must be distinct")
        if (
            len({item.volume_instance_fingerprint_sha256 for item in caches}) != 2
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
    """A host-control-plane executor, never a disposable-network attachment.

    The executor controls Docker through the separately signed Unix-socket
    policy. It is not a container and therefore may not be smuggled into the
    allocation graph as a second attachment to either disposable network.
    """

    executor_id: str = Field(pattern=_IDENTIFIER)
    placement: Literal["host_control_plane_v1"]


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
        if self.executor.placement != "host_control_plane_v1":
            raise ValueError("executor must remain a host control plane")
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
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    container_attach_protocol_sha256: str = Field(pattern=_SHA256)
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
            self.wrapper_manifest_sha256,
            self.target_delivery_map_sha256,
            self.container_attach_protocol_sha256,
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


class OciImageResolutionAttestationV1(_Model):
    """Trusted resolution proof for one immutable OCI index chain.

    Docker's Engine API can prove local references and a config image ID, but
    it does not expose the raw index child descriptor needed to prove index
    membership.  This separately signed attestation is that explicit trust
    boundary: it binds a pinned index to the selected linux/amd64 manifest and
    that manifest's config digest without retaining any raw registry document.
    """

    schema_version: Literal["rsd.oci-image-resolution-attestation.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    image: ImageReferenceV1
    registry_index_digest_sha256: str = Field(pattern=_SHA256)
    linux_amd64_manifest_digest_sha256: str = Field(pattern=_SHA256)
    config_digest_sha256: str = Field(pattern=_SHA256)
    platform: Literal["linux/amd64"]
    resolved_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("resolved_at")
    @classmethod
    def canonical_resolved_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_immutable_chain(self) -> Self:
        digest = self.image.reference.rsplit("@", 1)[1].removeprefix("sha256:")
        values = (
            self.registry_index_digest_sha256,
            self.linux_amd64_manifest_digest_sha256,
            self.config_digest_sha256,
        )
        if (
            digest != self.registry_index_digest_sha256
            or len(set(values)) != 3
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("OCI image resolution attestation is invalid")
        return self


def oci_image_resolution_attestation_message(
    attestation: OciImageResolutionAttestationV1,
) -> bytes:
    """Return canonical domain-separated bytes for a trusted OCI resolution."""

    attestation = _strict_canonical_model(attestation, OciImageResolutionAttestationV1)
    try:
        material = json.dumps(
            attestation.model_dump(mode="json", exclude={"signature_base64"}, warnings="error"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except Exception:
        raise ValueError("OCI image resolution attestation is invalid") from None
    return _OCI_IMAGE_RESOLUTION_ATTESTATION_DOMAIN + material


class DockerImagePolicyV1(_Model):
    """The three immutable OCI digests needed to identify a runnable image.

    A repository digest can name a multi-platform index.  A future Docker
    adapter therefore must prove the selected linux/amd64 manifest and config
    as well; a mutable tag is never an image identity at this boundary.
    """

    image: ImageReferenceV1
    registry_index_digest_sha256: str = Field(pattern=_SHA256)
    linux_amd64_manifest_digest_sha256: str = Field(pattern=_SHA256)
    config_digest_sha256: str = Field(pattern=_SHA256)
    resolution_attestation: OciImageResolutionAttestationV1

    @model_validator(mode="after")
    def exact_oci_chain(self) -> Self:
        digest = self.image.reference.rsplit("@", 1)[1].removeprefix("sha256:")
        values = (
            self.registry_index_digest_sha256,
            self.linux_amd64_manifest_digest_sha256,
            self.config_digest_sha256,
        )
        attestation = self.resolution_attestation
        if (
            digest != self.registry_index_digest_sha256
            or len(set(values)) != 3
            or attestation.image != self.image
            or attestation.registry_index_digest_sha256 != self.registry_index_digest_sha256
            or attestation.linux_amd64_manifest_digest_sha256
            != self.linux_amd64_manifest_digest_sha256
            or attestation.config_digest_sha256 != self.config_digest_sha256
        ):
            raise ValueError("Docker image policy is not a complete immutable OCI chain")
        return self


class DockerImageLocalEvidenceV1(_Model):
    """Redacted Engine evidence for both signed local OCI references.

    The two local reference checks establish index-reference/config and
    platform-manifest-reference/config resolution.  The nested trusted OCI
    resolution attestation is the *only* proof of index membership; Engine
    metadata is never represented as that proof.
    """

    schema_version: Literal["rsd.docker-image-local-evidence.v1"]
    resolution_attestation_sha256: str = Field(pattern=_SHA256)
    registry_index_reference: ImageReferenceV1
    linux_amd64_manifest_reference: ImageReferenceV1
    registry_index_digest_sha256: str = Field(pattern=_SHA256)
    linux_amd64_manifest_digest_sha256: str = Field(pattern=_SHA256)
    config_digest_sha256: str = Field(pattern=_SHA256)
    index_reference_inspected: Literal[True]
    platform_manifest_reference_inspected: Literal[True]
    operating_system: Literal["linux"]
    architecture: Literal["amd64"]

    @model_validator(mode="after")
    def exact_local_reference_projections(self) -> Self:
        index_digest = self.registry_index_reference.reference.rsplit("@", 1)[1].removeprefix(
            "sha256:"
        )
        manifest_digest = self.linux_amd64_manifest_reference.reference.rsplit("@", 1)[
            1
        ].removeprefix("sha256:")
        if (
            index_digest != self.registry_index_digest_sha256
            or manifest_digest != self.linux_amd64_manifest_digest_sha256
            or self.registry_index_reference.reference.rsplit("@", 1)[0]
            != self.linux_amd64_manifest_reference.reference.rsplit("@", 1)[0]
            or len(
                {
                    self.registry_index_digest_sha256,
                    self.linux_amd64_manifest_digest_sha256,
                    self.config_digest_sha256,
                }
            )
            != 3
        ):
            raise ValueError("Docker local image evidence is invalid")
        return self


class DockerImagePolicyBindingV1(_Model):
    """Receipt-safe commitment to one verified immutable OCI image policy.

    Runtime executor receipts must prove the exact selected OCI chain without
    embedding a second copy of the signed resolver attestation.  The full
    attestation remains inside the descriptor-safely loaded signed policy;
    this compact projection binds that policy's canonical hash and every
    identity digest needed to inspect the target container.
    """

    schema_version: Literal["rsd.docker-image-policy-binding.v1"]
    image_policy_sha256: str = Field(pattern=_SHA256)
    resolution_attestation_sha256: str = Field(pattern=_SHA256)
    image: ImageReferenceV1
    registry_index_digest_sha256: str = Field(pattern=_SHA256)
    linux_amd64_manifest_digest_sha256: str = Field(pattern=_SHA256)
    config_digest_sha256: str = Field(pattern=_SHA256)
    platform: Literal["linux/amd64"]

    @model_validator(mode="after")
    def exact_immutable_projection(self) -> Self:
        index_digest = self.image.reference.rsplit("@", 1)[1].removeprefix("sha256:")
        if (
            index_digest != self.registry_index_digest_sha256
            or len(
                {
                    self.image_policy_sha256,
                    self.resolution_attestation_sha256,
                    self.registry_index_digest_sha256,
                    self.linux_amd64_manifest_digest_sha256,
                    self.config_digest_sha256,
                }
            )
            != 5
        ):
            raise ValueError("Docker image policy binding is invalid")
        return self


def docker_image_policy_binding(policy: DockerImagePolicyV1) -> DockerImagePolicyBindingV1:
    """Return the only receipt-safe projection of a verified image policy."""

    if type(policy) is not DockerImagePolicyV1:
        raise ValueError("Docker image policy binding is invalid")
    return DockerImagePolicyBindingV1(
        schema_version="rsd.docker-image-policy-binding.v1",
        image_policy_sha256=canonical_sha256(policy),
        resolution_attestation_sha256=canonical_sha256(policy.resolution_attestation),
        image=policy.image,
        registry_index_digest_sha256=policy.registry_index_digest_sha256,
        linux_amd64_manifest_digest_sha256=policy.linux_amd64_manifest_digest_sha256,
        config_digest_sha256=policy.config_digest_sha256,
        platform="linux/amd64",
    )


def expected_docker_image_local_evidence(policy: DockerImagePolicyV1) -> DockerImageLocalEvidenceV1:
    """Return the exact receipt projection required after both local inspections.

    This is deliberately a pure policy projection.  A concrete Engine adapter
    must still perform each signed reference inspection before it may report
    this value; authorizers use the same projection to reject an executor
    receipt whose selected index, manifest, config, platform, or resolver
    attestation binding differs from the persisted signed policy.
    """

    if type(policy) is not DockerImagePolicyV1:
        raise ValueError("Docker local image evidence is invalid")
    try:
        repository = policy.image.reference.rsplit("@", 1)[0]
        manifest = ImageReferenceV1(
            reference=f"{repository}@sha256:{policy.linux_amd64_manifest_digest_sha256}"
        )
        return DockerImageLocalEvidenceV1(
            schema_version="rsd.docker-image-local-evidence.v1",
            resolution_attestation_sha256=canonical_sha256(policy.resolution_attestation),
            registry_index_reference=policy.image,
            linux_amd64_manifest_reference=manifest,
            registry_index_digest_sha256=policy.registry_index_digest_sha256,
            linux_amd64_manifest_digest_sha256=policy.linux_amd64_manifest_digest_sha256,
            config_digest_sha256=policy.config_digest_sha256,
            index_reference_inspected=True,
            platform_manifest_reference_inspected=True,
            operating_system="linux",
            architecture="amd64",
        )
    except (TypeError, ValueError):
        raise ValueError("Docker local image evidence is invalid") from None


class _DockerUnixSocketIdentityProjectionV1(_Model):
    """Internal canonical preimage for one pinned Unix-domain socket."""

    socket_path_sha256: str = Field(pattern=_SHA256)
    device: int = Field(ge=0)
    inode: int = Field(ge=1)
    owner_uid: int = Field(ge=0, le=2_147_483_647)
    group_gid: int = Field(ge=0, le=2_147_483_647)
    mode: int = Field(ge=0, le=0o777)


def docker_unix_socket_identity_sha256(
    *,
    socket_path_sha256: str,
    device: int,
    inode: int,
    owner_uid: int,
    group_gid: int,
    mode: int,
) -> str:
    """Return the signed, native identity of a Docker Engine socket."""

    projection = _DockerUnixSocketIdentityProjectionV1(
        socket_path_sha256=socket_path_sha256,
        device=device,
        inode=inode,
        owner_uid=owner_uid,
        group_gid=group_gid,
        mode=mode,
    )
    return _domain_sha256(_UNIX_SOCKET_IDENTITY_DOMAIN, projection)


class DockerUnixSocketPolicyV1(_Model):
    """One exact local Engine socket identity for a sealed executor.

    The path is an installation-scoped deployment value, but it is still a
    signed part of the policy: an allocation backend must never select an
    ambient Docker socket.  The device/inode pair deliberately makes a daemon
    restart or socket replacement fail closed until a newly reviewed policy is
    installed.
    """

    socket_path: str = Field(min_length=1, max_length=4096)
    socket_path_sha256: str = Field(pattern=_SHA256)
    socket_identity_sha256: str = Field(pattern=_SHA256)
    device: int = Field(ge=0)
    inode: int = Field(ge=1)
    owner_uid: int = Field(ge=0, le=2_147_483_647)
    group_gid: int = Field(ge=0, le=2_147_483_647)
    mode: int = Field(ge=0, le=0o777)
    endpoint_scheme: Literal["unix"]
    symlink_allowed: Literal[False]
    replacement_allowed: Literal[False]

    @field_validator("socket_path")
    @classmethod
    def canonical_socket_path(cls, value: str) -> str:
        path = Path(value)
        if (
            type(value) is not str
            or not path.is_absolute()
            or os.path.normpath(value) != value
            or "\x00" in value
        ):
            raise ValueError("Docker socket path is invalid")
        return value

    @model_validator(mode="after")
    def exact_socket_identity(self) -> Self:
        expected_path = _digest(os.fsencode(self.socket_path))
        if (
            self.socket_path_sha256 != expected_path
            or self.socket_identity_sha256
            != docker_unix_socket_identity_sha256(
                socket_path_sha256=self.socket_path_sha256,
                device=self.device,
                inode=self.inode,
                owner_uid=self.owner_uid,
                group_gid=self.group_gid,
                mode=self.mode,
            )
            or self.mode & 0o007 != 0
            or self.mode == 0
        ):
            raise ValueError("Docker socket policy is invalid")
        return self


class DockerEngineControlPolicyV1(_Model):
    """Signed closed Docker Engine API contract for allocation only.

    It intentionally models only the narrow endpoints required by empty
    allocation and its pre-existing PostgreSQL control container. Pull,
    delete, prune, update, restart, network-connect, logs, events, arbitrary
    exec, container create/start/attach, and shell execution are not
    representable. A later runtime effect requires a distinct signed policy.
    """

    schema_version: Literal["rsd.docker-engine-control-policy.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    executor_identity_sha256: str = Field(pattern=_SHA256)
    unix_socket: DockerUnixSocketPolicyV1
    api_version: str = Field(pattern=r"^[0-9]{1,3}\.[0-9]{1,3}$")
    engine_projection: DockerEngineFilteredProjectionV1
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    allowed_operations: tuple[
        Literal[
            "engine_ping",
            "engine_version",
            "engine_info",
            "image_inspect",
            "image_manifest_inspect",
            "network_create",
            "network_inspect",
            "volume_create",
            "volume_inspect",
            "container_inspect",
            "exec_create",
            "exec_inspect",
            "exec_start",
        ],
        ...,
    ]
    max_request_bytes: int = Field(ge=1, le=131_072)
    max_response_bytes: int = Field(ge=1, le=1_048_576)
    max_hijack_bytes: int = Field(ge=1, le=1_048_576)
    max_hijack_frames: int = Field(ge=1, le=65_536)
    request_timeout_seconds: int = Field(ge=1, le=60)
    hijack_timeout_seconds: int = Field(ge=1, le=60)
    hijack_absolute_timeout_seconds: int = Field(ge=1, le=300)
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("allowed_operations", mode="before")
    @classmethod
    def declared_operations(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="Docker Engine operations")

    @field_validator("created_at")
    @classmethod
    def canonical_created_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def closed_engine_api(self) -> Self:
        expected = (
            "engine_ping",
            "engine_version",
            "engine_info",
            "image_inspect",
            "image_manifest_inspect",
            "network_create",
            "network_inspect",
            "volume_create",
            "volume_inspect",
            "container_inspect",
            "exec_create",
            "exec_inspect",
            "exec_start",
        )
        if (
            self.allowed_operations != expected
            or self.engine_projection.api_version != self.api_version
            or self.engine_fingerprint_sha256
            != docker_engine_fingerprint_sha256(self.engine_projection)
            or self.max_response_bytes < self.max_request_bytes
            or self.hijack_absolute_timeout_seconds < self.hijack_timeout_seconds
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("Docker Engine control policy is invalid")
        return self


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
                grant.role != self.owner_role
                or grant.grantee not in self.role_names
                or grant.schema_name != self.schema_name
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


class PostgreSQLPreparedOperationV1(_Model):
    """One fixed psql stdin template and its value-free result projection."""

    operation_id: str = Field(pattern=_UUID)
    kind: Literal[
        "allocation_nologin_v1",
        "install_primary_scram_verifier_v1",
        "install_restore_scram_verifier_v1",
    ]
    psql_template_sha256: str = Field(pattern=_SHA256)
    result_projection_sha256: str = Field(pattern=_SHA256)
    stdin_protocol: Literal["postgresql_prepared_psql_stdin_v1"]
    secret_input: Literal[False, True]

    @model_validator(mode="after")
    def exact_operation_shape(self) -> Self:
        if (
            (self.kind == "allocation_nologin_v1" and self.secret_input is not False)
            or (
                self.kind
                in ("install_primary_scram_verifier_v1", "install_restore_scram_verifier_v1")
                and self.secret_input is not True
            )
            or self.psql_template_sha256 == self.result_projection_sha256
        ):
            raise ValueError("PostgreSQL prepared operation is invalid")
        return self


class PostgreSQLScramVerifierInstallV1(_Model):
    """Non-secret protocol for a verifier-only PostgreSQL password transition.

    The executor may derive a verifier in bounded memory from the authorized
    application password, but this model never represents the password,
    verifier, SQL text, psql output, or a database URI.
    """

    schema_version: Literal["rsd.postgresql-scram-verifier-install.v1"]
    database_identity: Literal["primary_database", "restore_database"]
    prepared_operation_id: str = Field(pattern=_UUID)
    application_password_reference_sha256: str = Field(pattern=_SHA256)
    algorithm: Literal["scram-sha-256"]
    iterations: int = Field(ge=4096, le=1_000_000)
    salt_bytes: int = Field(ge=16, le=64)
    derivation_scope: Literal["executor_bounded_memory_v1"]
    sink: Literal["postgresql_prepared_psql_stdin_verifier_v1"]
    plaintext_to_psql_allowed: Literal[False]
    verifier_in_receipt_allowed: Literal[False]
    sql_in_receipt_allowed: Literal[False]
    output_in_receipt_allowed: Literal[False]
    logs_allowed: Literal[False]
    template_sha256: str = Field(pattern=_SHA256)


class PostgreSQLScramVerifierInstallsV1(_Model):
    """Independent verifier-only sinks for the primary and restore databases."""

    primary_database: PostgreSQLScramVerifierInstallV1
    restore_database: PostgreSQLScramVerifierInstallV1

    @model_validator(mode="after")
    def independent_sinks(self) -> Self:
        primary = self.primary_database
        restore = self.restore_database
        if (
            primary.database_identity != "primary_database"
            or restore.database_identity != "restore_database"
            or primary.prepared_operation_id == restore.prepared_operation_id
            or primary.template_sha256 == restore.template_sha256
        ):
            raise ValueError("PostgreSQL SCRAM verifier sinks are invalid")
        return self


class PostgreSQLPreparedControlPolicyV2(_Model):
    """Signed, exact control-container/psql contract for future effects only."""

    schema_version: Literal["rsd.postgresql-prepared-control-policy.v2"]
    source_commit: str = Field(pattern=_COMMIT)
    executor_identity_sha256: str = Field(pattern=_SHA256)
    control_container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    control_image: DockerImagePolicyV1
    control_config_sha256: str = Field(pattern=_SHA256)
    unix_socket_identity_sha256: str = Field(pattern=_SHA256)
    psql_absolute_path: str = Field(pattern=r"^/[A-Za-z0-9._/-]{1,255}$")
    psql_binary_sha256: str = Field(pattern=_SHA256)
    psql_operating_system_user: str = Field(pattern=_IDENTIFIER)
    postgres_unix_socket_directory: str = Field(pattern=r"^/[A-Za-z0-9._/-]{1,255}$")
    maintenance_database: str = Field(pattern=_IDENTIFIER)
    fixed_psql_argv: tuple[str, ...] = Field(min_length=7, max_length=16)
    system_identifier: str = Field(pattern=r"^[0-9]{8,32}$")
    password_encryption: Literal["scram-sha-256"]
    statement_logging: Literal["disabled"]
    operations: tuple[
        PostgreSQLPreparedOperationV1,
        PostgreSQLPreparedOperationV1,
        PostgreSQLPreparedOperationV1,
    ]
    scram_verifier_installs: PostgreSQLScramVerifierInstallsV1
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("operations", "fixed_psql_argv", mode="before")
    @classmethod
    def declared_operations(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="PostgreSQL prepared operations")

    @field_validator("created_at")
    @classmethod
    def canonical_created_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_prepared_control(self) -> Self:
        allocation, primary_verifier, restore_verifier = self.operations
        values = (
            self.control_config_sha256,
            self.unix_socket_identity_sha256,
            self.psql_binary_sha256,
            allocation.psql_template_sha256,
            allocation.result_projection_sha256,
            primary_verifier.psql_template_sha256,
            primary_verifier.result_projection_sha256,
            restore_verifier.psql_template_sha256,
            restore_verifier.result_projection_sha256,
        )
        if (
            tuple(item.kind for item in self.operations)
            != (
                "allocation_nologin_v1",
                "install_primary_scram_verifier_v1",
                "install_restore_scram_verifier_v1",
            )
            or allocation.secret_input is not False
            or primary_verifier.secret_input is not True
            or restore_verifier.secret_input is not True
            or primary_verifier.operation_id
            != self.scram_verifier_installs.primary_database.prepared_operation_id
            or primary_verifier.psql_template_sha256
            != self.scram_verifier_installs.primary_database.template_sha256
            or restore_verifier.operation_id
            != self.scram_verifier_installs.restore_database.prepared_operation_id
            or restore_verifier.psql_template_sha256
            != self.scram_verifier_installs.restore_database.template_sha256
            or self.fixed_psql_argv
            != (
                self.psql_absolute_path,
                "-X",
                "-q",
                "-A",
                "-t",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                self.postgres_unix_socket_directory,
                "-U",
                self.psql_operating_system_user,
                "-d",
                self.maintenance_database,
                "-f",
                "-",
            )
            or len(set(values)) != len(values)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("PostgreSQL prepared control policy is invalid")
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
    postgres_uri_target_processes: tuple[Literal["primary_infisical"], Literal["restore_infisical"]]
    valkey_uri_target_processes: tuple[Literal["primary_infisical"], Literal["restore_infisical"]]
    infisical_target_process_environment_allowed: Literal[True]
    valkey_stdin_config_allowed: Literal[True]
    postgres_uri_target_process_environment_allowed: Literal[True]
    valkey_uri_target_process_environment_allowed: Literal[True]
    postgres_connection_uri_environment_variable: Literal["DB_CONNECTION_URI"]
    valkey_connection_uri_environment_variable: Literal["REDIS_URL"]
    valkey_stdin_configuration_directive: Literal["requirepass"]
    postgres_scram_verifier_executor_derivation_allowed: Literal[True]
    postgres_scram_verifier_psql_stdin_allowed: Literal[True]
    postgres_plaintext_password_to_psql_allowed: Literal[False]
    postgres_verifier_in_receipt_allowed: Literal[False]
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
        "postgres_uri_target_processes",
        "valkey_uri_target_processes",
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
            or self.postgres_uri_target_processes != ("primary_infisical", "restore_infisical")
            or self.valkey_uri_target_processes != ("primary_infisical", "restore_infisical")
            or self.infisical_target_process_environment_allowed is not True
            or self.valkey_stdin_config_allowed is not True
            or self.postgres_uri_target_process_environment_allowed is not True
            or self.valkey_uri_target_process_environment_allowed is not True
            or self.postgres_scram_verifier_executor_derivation_allowed is not True
            or self.postgres_scram_verifier_psql_stdin_allowed is not True
            or self.postgres_plaintext_password_to_psql_allowed is not False
            or self.postgres_verifier_in_receipt_allowed is not False
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
    docker_engine_control_policy_sha256: str = Field(pattern=_SHA256)
    postgres_control_policy_sha256: str = Field(pattern=_SHA256)
    postgres_prepared_control_policy_sha256: str = Field(pattern=_SHA256)

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
    prepared_control_policy_sha256: str = Field(pattern=_SHA256)

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
                grant.role != self.owner_role
                or grant.grantee not in self.role_names
                or grant.schema_name != self.schema_name
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
    docker_engine_control_policy_sha256: str = Field(pattern=_SHA256)

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
            or self.plan.postgres.prepared_control_policy_sha256
            != self.evidence.postgres_prepared_control_policy_sha256
            or self.plan.docker_engine_control_policy_sha256
            != self.evidence.docker_engine_control_policy_sha256
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


class DockerEngineFilteredProjectionV1(_Model):
    """The small, canonical subset of Docker daemon identity used for binding.

    Docker reports ``Info.ID`` as a daemon-defined string rather than a
    container-style 64-hex ID.  Raw daemon responses, labels, paths and all
    host configuration are deliberately outside this projection.
    """

    daemon_id: str = Field(pattern=_DOCKER_DAEMON_ID)
    api_version: str = Field(pattern=r"^[0-9]{1,3}\.[0-9]{1,3}$")
    operating_system: Literal["linux"]
    architecture: Literal["amd64"]


def docker_engine_fingerprint_sha256(projection: DockerEngineFilteredProjectionV1) -> str:
    """Derive the engine identity from a typed filtered projection only."""

    if type(projection) is not DockerEngineFilteredProjectionV1:
        raise ValueError("engine projection is invalid")
    return _domain_sha256(_ENGINE_FINGERPRINT_DOMAIN, projection)


class AllocatedVolumeObservationV1(_Model):
    """A native named-volume observation with no fictional Docker volume ID.

    Docker's inspect response identifies a named volume by its name and
    metadata, not by a stable 64-hex workload-style ID.  The derived
    fingerprint deliberately excludes ``Mountpoint`` and labels, preventing a
    host path or opaque label from entering public receipts.
    """

    name: str = Field(pattern=_IDENTIFIER)
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    driver: Literal["local"]
    scope: Literal["local"]
    created_at: str
    options: tuple[NetworkOptionV1, ...] = Field(default=(), max_length=16)
    volume_instance_fingerprint_sha256: str = Field(pattern=_SHA256)

    @field_validator("created_at")
    @classmethod
    def canonical_created_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @field_validator("options", mode="before")
    @classmethod
    def declared_options(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="observed volume options")

    @model_validator(mode="after")
    def exact_configuration(self) -> Self:
        pairs = tuple((option.key, option.value) for option in self.options)
        projection = _VolumeInstanceProjectionV1(
            name=self.name,
            engine_fingerprint_sha256=self.engine_fingerprint_sha256,
            driver=self.driver,
            scope=self.scope,
            created_at=self.created_at,
            options=self.options,
        )
        if (
            pairs != tuple(sorted(pairs))
            or len(set(pairs)) != len(pairs)
            or self.volume_instance_fingerprint_sha256
            != _domain_sha256(_VOLUME_INSTANCE_FINGERPRINT_DOMAIN, projection)
        ):
            raise ValueError("observed volume options must be canonical")
        return self


class _VolumeInstanceProjectionV1(_Model):
    """Internal canonical preimage for a public named-volume fingerprint."""

    name: str = Field(pattern=_IDENTIFIER)
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    driver: Literal["local"]
    scope: Literal["local"]
    created_at: str
    options: tuple[NetworkOptionV1, ...] = Field(default=(), max_length=16)


def docker_volume_instance_fingerprint_sha256(
    *,
    name: str,
    engine_fingerprint_sha256: str,
    driver: Literal["local"],
    scope: Literal["local"],
    created_at: str,
    options: tuple[NetworkOptionV1, ...],
) -> str:
    """Compute the exact value accepted by ``AllocatedVolumeObservationV1``."""

    projection = _VolumeInstanceProjectionV1(
        name=name,
        engine_fingerprint_sha256=engine_fingerprint_sha256,
        driver=driver,
        scope=scope,
        created_at=created_at,
        options=options,
    )
    return _domain_sha256(_VOLUME_INSTANCE_FINGERPRINT_DOMAIN, projection)


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
    prepared_operation_id: str = Field(pattern=_UUID)
    prepared_operation_result_sha256: str = Field(pattern=_SHA256)
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
    """Native Docker daemon identity and its filtered, domain-bound digest."""

    projection: DockerEngineFilteredProjectionV1
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def exact_derived_fingerprint(self) -> Self:
        if self.engine_fingerprint_sha256 != docker_engine_fingerprint_sha256(self.projection):
            raise ValueError("engine identity fingerprint is invalid")
        return self


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
            or self.primary_cache_volume.volume_instance_fingerprint_sha256
            == self.restore_cache_volume.volume_instance_fingerprint_sha256
        ):
            raise ValueError("allocated resources must be distinct")
        return self


class AllocationExecutorReceiptV1(_Model):
    """Executor-attested filtered evidence for a zero-secret allocation.

    This is deliberately separate from the outer effect receipt.  The outer
    authorizer validates this signature against the installed executor key,
    rather than trusting a callback's raw Engine JSON or a hash-only bridge.
    """

    schema_version: Literal["rsd.allocation-executor-receipt.v1"]
    operation_scope: Literal["allocate_isolated_empty_resources_v2"]
    allocation_operation_id: str = Field(pattern=_UUID)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    idempotency_key: str = Field(pattern=_SHA256)
    executor_id: str = Field(pattern=_IDENTIFIER)
    engine_control_policy_sha256: str = Field(pattern=_SHA256)
    postgres_prepared_control_policy_sha256: str = Field(pattern=_SHA256)
    host_fingerprint_sha256: str = Field(pattern=_SHA256)
    engine: EngineIdentityObservationV1
    control_image_local_evidence: DockerImageLocalEvidenceV1
    allocated_resources: AllocatedResourceSetV2
    allocated_resources_projection_sha256: str = Field(pattern=_SHA256)
    engine_operation_journal_sha256: str = Field(pattern=_SHA256)
    completed_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("completed_at")
    @classmethod
    def canonical_completed_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def redacted_filtered_projection(self) -> Self:
        values = (
            self.engine_control_policy_sha256,
            self.postgres_prepared_control_policy_sha256,
            self.host_fingerprint_sha256,
            self.allocated_resources_projection_sha256,
            self.engine_operation_journal_sha256,
        )
        if (
            len(set(values)) != len(values)
            or self.allocated_resources.engine != self.engine
            or self.allocated_resources_projection_sha256
            != canonical_sha256(self.allocated_resources)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("allocation executor receipt is invalid")
        return self


def allocation_executor_receipt_message(receipt: AllocationExecutorReceiptV1) -> bytes:
    """Return the exact public, domain-separated allocation attestation bytes.

    The remote executor daemon uses this helper to sign its typed filtered
    evidence.  Keeping the preimage beside the receipt model prevents a
    hash-only transport bridge or a non-public authorization helper from becoming
    the effective signature specification.
    """

    receipt = _strict_canonical_model(receipt, AllocationExecutorReceiptV1)
    try:
        material = json.dumps(
            receipt.model_dump(mode="json", exclude={"signature_base64"}, warnings="error"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except Exception:
        raise ValueError("allocation executor receipt is invalid") from None
    return _ALLOCATION_EXECUTOR_RECEIPT_DOMAIN + material


def _executor_receipt_message(domain: bytes, receipt: _Model) -> bytes:
    """Render the common canonical preimage for a typed executor receipt."""

    try:
        return domain + json.dumps(
            receipt.model_dump(mode="json", exclude={"signature_base64"}, warnings="error"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except Exception:
        raise ValueError("executor receipt is invalid") from None


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
    executor_receipt_sha256: str = Field(pattern=_SHA256)
    executor_receipt: AllocationExecutorReceiptV1
    effect_receipt_sha256: str = Field(pattern=_SHA256)
    completed_at: str

    @field_validator("completed_at")
    @classmethod
    def completed_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_executor_receipt(self) -> Self:
        if self.executor_receipt_sha256 != canonical_sha256(self.executor_receipt):
            raise ValueError("allocation effect receipt is invalid")
        return self


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


class ObservedRestoreDatabaseAttestationV1(_Model):
    """Signed, post-backup observation of the independent restore database.

    Allocation intentionally observes only the empty primary database.  A
    later backup/restore operation must therefore introduce a separate,
    signed predecessor before either materialization or a fresh start can use
    a restore login transition.  The model carries only stable PostgreSQL
    identifiers, prepared-operation commitments, and value-free backup/
    restore commitments; it cannot carry a dump, connection URI, verifier, or
    credential.
    """

    schema_version: Literal["rsd.observed-restore-database-attestation.v1"]
    operation_kind: Literal["restore_database_observation_v1"]
    restore_observation_operation_id: str = Field(pattern=_UUID)
    allocation_operation_id: str = Field(pattern=_UUID)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    allocation_effect_receipt_sha256: str = Field(pattern=_SHA256)
    observed_allocation_attestation_sha256: str = Field(pattern=_SHA256)
    journal_uuid: str = Field(pattern=_UUID)
    source_database_observation_sha256: str = Field(pattern=_SHA256)
    source_backup_commitment_sha256: str = Field(pattern=_SHA256)
    restore_commitment_sha256: str = Field(pattern=_SHA256)
    authority: str
    restore_database: AllocatedPostgreSQLObservationV1
    observed_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("authority")
    @classmethod
    def canonical_authority(cls, value: str) -> str:
        return _authority(value, schemes=frozenset({"postgresql"}))

    @field_validator("observed_at")
    @classmethod
    def observation_time(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def binds_distinct_restore_operation(self) -> Self:
        commitments = (
            self.allocation_intent_sha256,
            self.allocation_effect_receipt_sha256,
            self.observed_allocation_attestation_sha256,
            self.source_database_observation_sha256,
            self.source_backup_commitment_sha256,
            self.restore_commitment_sha256,
        )
        if (
            self.restore_observation_operation_id == self.allocation_operation_id
            or len(set(commitments)) != len(commitments)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("observed restore database attestation is invalid")
        return self


def observed_restore_database_attestation_sha256(
    attestation: ObservedRestoreDatabaseAttestationV1,
) -> str:
    """Return the domain-separated commitment for one restore observation."""

    if type(attestation) is not ObservedRestoreDatabaseAttestationV1:
        raise ValueError("observed restore database attestation is invalid")
    return _domain_sha256(_OBSERVED_RESTORE_DATABASE_ATTESTATION_DOMAIN, attestation)


def validate_observed_restore_database_transition(
    intent: AllocationIntentV2,
    receipt: AllocationEffectReceiptV2,
    allocation: ObservedAllocationAttestationV1,
    restore: ObservedRestoreDatabaseAttestationV1,
) -> None:
    """Require an exact, independent backup-to-restore observation chain."""

    if (
        type(intent) is not AllocationIntentV2
        or type(receipt) is not AllocationEffectReceiptV2
        or type(allocation) is not ObservedAllocationAttestationV1
        or type(restore) is not ObservedRestoreDatabaseAttestationV1
    ):
        raise ValueError("restore database observation transition is invalid")
    source = allocation.allocated_resources.postgres
    observed = restore.restore_database
    if (
        restore.allocation_operation_id != intent.allocation_operation_id
        or restore.allocation_intent_sha256 != allocation_intent_sha256(intent)
        or restore.allocation_effect_receipt_sha256 != allocation_effect_receipt_sha256(receipt)
        or restore.observed_allocation_attestation_sha256
        != observed_allocation_attestation_sha256(allocation)
        or restore.journal_uuid != intent.journal_uuid
        or restore.source_database_observation_sha256 != canonical_sha256(source)
        or restore.authority != intent.plan.postgres.authority
        or observed.system_identifier != source.system_identifier
        or not observed.database_name.startswith(intent.plan.postgres.restore_database_prefix)
        or observed.database_name == source.database_name
        or observed.database_oid == source.database_oid
        or observed.schema_name != source.schema_name
        or observed.owner_role == source.owner_role
        or observed.owner_role_oid == source.owner_role_oid
        or observed.application_role == source.application_role
        or observed.application_role_oid == source.application_role_oid
    ):
        raise ValueError("restore database observation transition is invalid")


class PostgreSQLLoginTransitionIntentV1(_Model):
    """Signed, observed-OID-bound authorization for the one login transition.

    The model intentionally states only role state and verifier presence.  It
    never carries a password, verifier text, SQL fragment, DSN, or URI.
    """

    schema_version: Literal["rsd.postgresql-login-transition-intent.v1"]
    transition_kind: Literal["enable_application_login_with_provider_verifier_v1"]
    database_identity: Literal["primary_database", "restore_database"]
    prepared_operation_id: str = Field(pattern=_UUID)
    system_identifier: str = Field(pattern=r"^[0-9]{8,32}$")
    database_name: str = Field(pattern=_IDENTIFIER)
    database_oid: int = Field(ge=1)
    schema_oid: int = Field(ge=1)
    owner_role: str = Field(pattern=_IDENTIFIER)
    owner_role_oid: int = Field(ge=1)
    application_role: str = Field(pattern=_IDENTIFIER)
    application_role_oid: int = Field(ge=1)
    application_password_reference_sha256: str = Field(pattern=_SHA256)
    prepared_control_policy_sha256: str = Field(pattern=_SHA256)
    scram_verifier_install: PostgreSQLScramVerifierInstallV1
    owner_can_login: Literal[False]
    owner_password_absent: Literal[True]
    application_can_login: Literal[True]
    application_password_verifier_installed: Literal[True]

    @model_validator(mode="after")
    def exact_secret_free_transition(self) -> Self:
        if (
            self.owner_role == self.application_role
            or self.owner_role_oid == self.application_role_oid
            or self.scram_verifier_install.database_identity != self.database_identity
            or self.scram_verifier_install.prepared_operation_id != self.prepared_operation_id
            or self.scram_verifier_install.application_password_reference_sha256
            != self.application_password_reference_sha256
        ):
            raise ValueError("PostgreSQL login transition is invalid")
        return self


class PostgreSQLLoginTransitionReceiptV1(_Model):
    """Value-free effect evidence for the one prepared login transition."""

    schema_version: Literal["rsd.postgresql-login-transition-receipt.v1"]
    database_identity: Literal["primary_database", "restore_database"]
    prepared_operation_id: str = Field(pattern=_UUID)
    system_identifier: str = Field(pattern=r"^[0-9]{8,32}$")
    database_name: str = Field(pattern=_IDENTIFIER)
    database_oid: int = Field(ge=1)
    schema_oid: int = Field(ge=1)
    owner_role: str = Field(pattern=_IDENTIFIER)
    owner_role_oid: int = Field(ge=1)
    application_role: str = Field(pattern=_IDENTIFIER)
    application_role_oid: int = Field(ge=1)
    application_password_reference_sha256: str = Field(pattern=_SHA256)
    prepared_control_policy_sha256: str = Field(pattern=_SHA256)
    prepared_operation_result_sha256: str = Field(pattern=_SHA256)
    owner_can_login: Literal[False]
    owner_password_absent: Literal[True]
    application_can_login: Literal[True]
    application_password_verifier_installed: Literal[True]

    @model_validator(mode="after")
    def exact_secret_free_receipt(self) -> Self:
        if (
            self.owner_role == self.application_role
            or self.owner_role_oid == self.application_role_oid
            or self.prepared_control_policy_sha256 == self.prepared_operation_result_sha256
        ):
            raise ValueError("PostgreSQL login transition receipt is invalid")
        return self


def _canonical_uri_authority_suffix_utf8_byte_count(*, authority: str, scheme: str) -> int:
    """Return the exact canonical authority suffix width for one URI grammar.

    ``urlsplit().hostname`` deliberately removes brackets from IPv6 literals;
    a rendered URI must retain those brackets.  Revalidate the authority and
    count the canonical suffix as it will appear on the wire instead of
    reconstructing a secret-bearing URI or relying on parsed host internals.
    """

    prefix = scheme + ":" + "//"
    canonical = _authority(authority, schemes=frozenset({scheme}))
    if not canonical.startswith(prefix):
        raise ValueError("URI grammar authority is invalid")
    return len(canonical.removeprefix(prefix).encode("utf-8"))


def postgresql_connection_uri_rendered_byte_count(
    *, authority: str, application_role: str, database_name: str
) -> int:
    """Return the exact URI size without ever assembling a provider value.

    The password placeholder has the fixed canonical Base64URL width of the
    approved application-password material.  This is a grammar commitment,
    not a URI and not a value-derived fingerprint.
    """

    authority_bytes = _canonical_uri_authority_suffix_utf8_byte_count(
        authority=authority, scheme="postgresql"
    )
    return (
        len(b"postgresql:")
        + len(b"//")
        + len(application_role.encode("utf-8"))
        + 1  # credential delimiter
        + 43  # canonical unpadded Base64URL application-password width
        + 1  # authority delimiter
        + authority_bytes
        + 1  # database path delimiter
        + len(database_name.encode("utf-8"))
    )


def valkey_connection_uri_rendered_byte_count(*, authority: str, database_index: int) -> int:
    """Return the exact Valkey URI size without constructing its password."""

    authority_bytes = _canonical_uri_authority_suffix_utf8_byte_count(
        authority=authority, scheme="redis"
    )
    return (
        len(b"redis:")
        + len(b"//")
        + 1  # empty username delimiter
        + 43  # canonical unpadded Base64URL Valkey password width
        + 1  # authority delimiter
        + authority_bytes
        + 1  # database path delimiter
        + len(str(database_index).encode("ascii"))
    )


def valkey_static_authority(static_ipv4: str) -> str:
    """Render the one canonical planned Valkey authority without a credential.

    Static component placement is an IPv4-only allocation contract.  Keeping
    the scheme and port constants separate also prevents a caller from
    treating the URI grammar as an arbitrary listener selection.
    """

    if type(static_ipv4) is not str:
        raise ValueError("Valkey static authority is invalid")
    try:
        address = ipaddress.IPv4Address(static_ipv4)
    except ipaddress.AddressValueError:
        raise ValueError("Valkey static authority is invalid") from None
    return f"{_VALKEY_SCHEME}//{address}:{_VALKEY_FIXED_PORT}"


class PostgreSQLConnectionUriGrammarV1(_Model):
    """Value-free exact grammar for one target-only PostgreSQL URI.

    A future effect may construct this URI only in its bounded memory and
    place it only in the named target-process environment.  The model never
    stores, returns, fingerprints, or serializes the resulting URI.
    """

    schema_version: Literal["rsd.postgresql-connection-uri-grammar.v1"]
    database_identity: Literal["primary_database", "restore_database"]
    authority: str
    database_name: str = Field(pattern=_IDENTIFIER)
    application_role: str = Field(pattern=_IDENTIFIER)
    application_password_reference_sha256: str = Field(pattern=_SHA256)
    prepared_operation_id: str = Field(pattern=_UUID)
    target_process: Literal["primary_infisical", "restore_infisical"]
    environment_variable: Literal["DB_CONNECTION_URI"]
    uri_grammar: Literal["postgresql_user_password_authority_database_v1"]
    application_password_format: Literal["postgres_application_password_base64url_32_v1"]
    application_password_encoded_byte_count: Literal[43]
    rendered_uri_byte_count: int = Field(ge=1, le=1024)
    return_uri_allowed: Literal[False]
    persistent_storage_allowed: Literal[False]
    logging_allowed: Literal[False]
    public_artifact_allowed: Literal[False]

    @field_validator("authority")
    @classmethod
    def canonical_postgres(cls, value: str) -> str:
        return _authority(value, schemes=frozenset({"postgresql"}))

    @model_validator(mode="after")
    def exact_value_free_grammar(self) -> Self:
        expected_target = (
            "primary_infisical"
            if self.database_identity == "primary_database"
            else "restore_infisical"
        )
        if (
            self.target_process != expected_target
            or self.rendered_uri_byte_count
            != postgresql_connection_uri_rendered_byte_count(
                authority=self.authority,
                application_role=self.application_role,
                database_name=self.database_name,
            )
        ):
            raise ValueError("PostgreSQL URI grammar is invalid")
        return self


class ValkeyConnectionUriGrammarV1(_Model):
    """Value-free exact grammar for an Infisical-to-Valkey target URI."""

    schema_version: Literal["rsd.valkey-connection-uri-grammar.v1"]
    cache_identity: Literal["primary_valkey", "restore_valkey"]
    authority: str
    database_index: int = Field(ge=0, le=15)
    password_reference_sha256: str = Field(pattern=_SHA256)
    target_process: Literal["primary_infisical", "restore_infisical"]
    environment_variable: Literal["REDIS_URL"]
    uri_grammar: Literal["redis_password_authority_database_v1"]
    password_format: Literal["valkey_password_base64url_32_v1"]
    password_encoded_byte_count: Literal[43]
    rendered_uri_byte_count: int = Field(ge=1, le=1024)
    return_uri_allowed: Literal[False]
    persistent_storage_allowed: Literal[False]
    logging_allowed: Literal[False]
    public_artifact_allowed: Literal[False]

    @field_validator("authority")
    @classmethod
    def canonical_valkey(cls, value: str) -> str:
        return _authority(value, schemes=frozenset({"redis"}))

    @model_validator(mode="after")
    def exact_value_free_grammar(self) -> Self:
        expected_target = (
            "primary_infisical" if self.cache_identity == "primary_valkey" else "restore_infisical"
        )
        if (
            self.target_process != expected_target
            or self.rendered_uri_byte_count
            != valkey_connection_uri_rendered_byte_count(
                authority=self.authority, database_index=self.database_index
            )
        ):
            raise ValueError("Valkey URI grammar is invalid")
        return self


def runtime_connection_uri_grammar_sha256(
    grammar: PostgreSQLConnectionUriGrammarV1 | ValkeyConnectionUriGrammarV1,
) -> str:
    """Commit one value-free target URI grammar under its explicit domain.

    This helper intentionally accepts only the two concrete grammar models.
    It never renders a URI and therefore cannot acquire a copy of a password.
    """

    if type(grammar) not in {PostgreSQLConnectionUriGrammarV1, ValkeyConnectionUriGrammarV1}:
        raise ValueError("runtime URI grammar is invalid")
    return _domain_sha256(_URI_GRAMMAR_DOMAIN, grammar)


class PostgreSQLRuntimeDatabaseIdentityV1(_Model):
    """One observed-OID-bound database transition and target URI grammar."""

    database_identity: Literal["primary_database", "restore_database"]
    observation_binding_sha256: str = Field(pattern=_SHA256)
    schema_oid: int = Field(ge=1)
    login_transition: PostgreSQLLoginTransitionIntentV1
    connection_uri: PostgreSQLConnectionUriGrammarV1

    @model_validator(mode="after")
    def exact_observed_identity(self) -> Self:
        if (
            self.login_transition.database_identity != self.database_identity
            or self.login_transition.schema_oid != self.schema_oid
            or self.connection_uri.database_identity != self.database_identity
            or self.connection_uri.database_name != self.login_transition.database_name
            or self.connection_uri.application_role != self.login_transition.application_role
            or self.connection_uri.application_password_reference_sha256
            != self.login_transition.application_password_reference_sha256
            or self.connection_uri.prepared_operation_id
            != self.login_transition.prepared_operation_id
        ):
            raise ValueError("PostgreSQL runtime identity is invalid")
        return self


class PostgreSQLRuntimeDatabaseIdentitiesV1(_Model):
    """The primary and restore identities must remain independent.

    The currently implemented allocation stage observes only the primary
    stage database.  A restore identity is still modeled separately here so a
    future restore observation cannot be replaced by the primary route.
    """

    primary_database: PostgreSQLRuntimeDatabaseIdentityV1
    restore_database: PostgreSQLRuntimeDatabaseIdentityV1

    @model_validator(mode="after")
    def independent_database_identities(self) -> Self:
        primary = self.primary_database.login_transition
        restore = self.restore_database.login_transition
        if (
            self.primary_database.database_identity != "primary_database"
            or self.restore_database.database_identity != "restore_database"
            or primary.database_name == restore.database_name
            or primary.database_oid == restore.database_oid
            or primary.application_role == restore.application_role
            or primary.application_role_oid == restore.application_role_oid
            or primary.prepared_operation_id == restore.prepared_operation_id
            or self.primary_database.observation_binding_sha256
            == self.restore_database.observation_binding_sha256
        ):
            raise ValueError("PostgreSQL runtime identities are invalid")
        return self


class PostgreSQLLoginTransitionIntentsV1(_Model):
    """Canonical primary/restore transition set exposed to a bounded lease."""

    primary_database: PostgreSQLLoginTransitionIntentV1
    restore_database: PostgreSQLLoginTransitionIntentV1

    @model_validator(mode="after")
    def exact_transition_set(self) -> Self:
        if (
            self.primary_database.database_identity != "primary_database"
            or self.restore_database.database_identity != "restore_database"
            or self.primary_database == self.restore_database
        ):
            raise ValueError("PostgreSQL login transition set is invalid")
        return self


class PostgreSQLLoginTransitionReceiptsV1(_Model):
    """Value-free receipts for both independent database transitions."""

    primary_database: PostgreSQLLoginTransitionReceiptV1
    restore_database: PostgreSQLLoginTransitionReceiptV1

    @model_validator(mode="after")
    def exact_receipt_set(self) -> Self:
        if (
            self.primary_database.database_identity != "primary_database"
            or self.restore_database.database_identity != "restore_database"
            or self.primary_database == self.restore_database
        ):
            raise ValueError("PostgreSQL login transition receipt set is invalid")
        return self


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
            "primary_infisical": (
                "encryption_key",
                "auth_secret",
                "primary_valkey_password",
                "postgres_application_password",
            ),
            "primary_valkey": ("primary_valkey_password",),
            "restore_infisical": (
                "encryption_key",
                "auth_secret",
                "restore_valkey_password",
                "postgres_application_password",
            ),
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


class DockerNamedVolumeMountV1(_Model):
    """The sole mutable-storage mount shape allowed in this lifecycle.

    Only the allocated named Valkey volumes may be mounted, at ``/data`` and
    read/write.  Bind sources, tmpfs configuration and mount propagation are
    intentionally not representable, so a raw Docker ``Mountpoint`` can never
    leak into a plan or receipt.
    """

    mount_type: Literal["volume"]
    source_volume_name: str = Field(pattern=_IDENTIFIER)
    target_path: Literal["/data"]
    read_only: Literal[False]
    bind_allowed: Literal[False]
    tmpfs_allowed: Literal[False]
    propagation: Literal["none"]


class ContainerBootstrapAttachProtocolV1(_Model):
    """Signed, local daemon-to-container bootstrap framing contract.

    This is intentionally distinct from the Mac-to-daemon remote-session framing.  It
    describes only a future, container-stdin attach boundary and does not
    create a socket, container, process, or secret-bearing frame.
    """

    schema_version: Literal["rsd.container-bootstrap-attach-protocol.v1"]
    protocol_name: Literal["rsd_container_bootstrap_attach_v1"]
    frame_magic: Literal["ONCA"]
    frame_version: Literal[1]
    metadata_encoding: Literal["canonical_json_utf8_v1"]
    allowed_operation_scopes: tuple[
        Literal["materialize_and_start_runtime_v1"], Literal["start_runtime_v2"]
    ]
    ready_state: Literal["ready_v1"]
    claim_state: Literal["claimed_v1"]
    terminal_ack_state: Literal["terminal_ack_v1"]
    ambiguous_state: Literal["attach_ambiguous_v1"]
    max_metadata_bytes: int = Field(ge=256, le=16_384)
    max_chunk_bytes: int = Field(ge=1, le=65_536)
    max_chunks_per_target: int = Field(ge=1, le=4)
    max_total_secret_bytes: int = Field(ge=1, le=262_144)
    ready_timeout_seconds: int = Field(ge=1, le=60)
    claim_timeout_seconds: int = Field(ge=1, le=60)
    terminal_ack_timeout_seconds: int = Field(ge=1, le=60)
    eof_required_after_terminal_ack: Literal[True]
    chunk_order_required: Literal[True]
    replay_allowed: Literal[False]
    auto_retry_after_secret_delivery_allowed: Literal[False]
    secret_persistence_allowed: Literal[False]
    secret_logging_allowed: Literal[False]
    secret_receipt_allowed: Literal[False]
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("allowed_operation_scopes", mode="before")
    @classmethod
    def declared_scopes(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container attach operation scopes")

    @field_validator("created_at")
    @classmethod
    def canonical_created_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_bounded_protocol(self) -> Self:
        if (
            self.allowed_operation_scopes
            != ("materialize_and_start_runtime_v1", "start_runtime_v2")
            or self.max_total_secret_bytes < self.max_chunk_bytes
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("container bootstrap attach protocol is invalid")
        return self


def container_bootstrap_attach_protocol_sha256(
    protocol: ContainerBootstrapAttachProtocolV1,
) -> str:
    """Return the domain-separated commitment for the local attach contract."""

    if type(protocol) is not ContainerBootstrapAttachProtocolV1:
        raise ValueError("container bootstrap attach protocol is invalid")
    return _domain_sha256(_LOCAL_ATTACH_PROTOCOL_DOMAIN, protocol)


class ContainerWrapperRuntimeRequirementsV1(_Model):
    """Runtime requirements declared for wrapper bytes, never observed here."""

    architecture: Literal["linux/amd64"]
    executable_mode: Literal["0755"]
    requires_exec_form: Literal[True]
    requires_private_pid_namespace: Literal[True]
    requires_read_only_root_filesystem: Literal[True]
    requires_log_driver_none: Literal[True]
    requires_restart_policy_no: Literal[True]
    writable_disk_allowed: Literal[False]
    secret_file_allowed: Literal[False]
    secret_log_allowed: Literal[False]


class ContainerWrapperPid1PolicyV1(_Model):
    """The exact lifecycle behavior a future wrapper must prove at runtime."""

    schema_version: Literal["rsd.container-wrapper-pid1-policy.v1"]
    signal_order: tuple[Literal["SIGTERM"], Literal["SIGINT"]]
    forwards_signals_to_child: Literal[True]
    reaps_children: Literal[True]
    propagates_child_exit_status: Literal[True]
    terminal_ack_before_exit_required: Literal[True]
    shutdown_timeout_seconds: int = Field(ge=1, le=300)

    @field_validator("signal_order", mode="before")
    @classmethod
    def declared_signals(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container wrapper signals")

    @model_validator(mode="after")
    def exact_pid1_policy(self) -> Self:
        if self.signal_order != ("SIGTERM", "SIGINT"):
            raise ValueError("container wrapper PID1 policy is invalid")
        return self


def _merged_container_argv_sha256(
    *,
    wrapper_argv_prefix: tuple[str, ...],
    base_entrypoint: tuple[str, ...],
    base_command: tuple[str, ...],
) -> str:
    """Commit the exact exec-form merge without materializing a command line."""

    return _digest(
        json.dumps(
            wrapper_argv_prefix + base_entrypoint + base_command,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


class ContainerBootstrapWrapperArtifactV1(_Model):
    """One immutable wrapper/derived-image declaration.

    Every field is a signed planned commitment.  It intentionally cannot be
    mistaken for proof that bytes were built, installed, inspected, or run.
    """

    component: Literal[
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ]
    artifact_sha256: str = Field(pattern=_SHA256)
    artifact_byte_count: int = Field(ge=1, le=16_777_216)
    build_provenance_sha256: str = Field(pattern=_SHA256)
    build_recipe_sha256: str = Field(pattern=_SHA256)
    base_image_policy: DockerImagePolicyV1
    derived_image_policy: DockerImagePolicyV1
    executable_path: str = Field(pattern=r"^/[A-Za-z0-9._/-]{1,255}$")
    wrapper_argv_prefix: tuple[str, ...] = Field(min_length=1, max_length=16)
    base_entrypoint: tuple[str, ...] = Field(default=(), max_length=16)
    base_command: tuple[str, ...] = Field(default=(), max_length=32)
    entrypoint_command_merge: Literal["exec_wrapper_then_base_entrypoint_and_cmd_v1"]
    merged_argv_sha256: str = Field(pattern=_SHA256)
    runtime_requirements: ContainerWrapperRuntimeRequirementsV1
    pid1_policy: ContainerWrapperPid1PolicyV1
    attach_protocol_sha256: str = Field(pattern=_SHA256)
    artifact_binding_sha256: str = Field(pattern=_SHA256)

    @field_validator("wrapper_argv_prefix", "base_entrypoint", "base_command", mode="before")
    @classmethod
    def declared_argv(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container wrapper argv")

    @model_validator(mode="after")
    def exact_immutable_wrapper_binding(self) -> Self:
        if (
            self.base_image_policy == self.derived_image_policy
            or self.base_image_policy.image == self.derived_image_policy.image
            or self.wrapper_argv_prefix[0] != self.executable_path
            or not self.base_entrypoint + self.base_command
            or self.merged_argv_sha256
            != _merged_container_argv_sha256(
                wrapper_argv_prefix=self.wrapper_argv_prefix,
                base_entrypoint=self.base_entrypoint,
                base_command=self.base_command,
            )
            or self.artifact_binding_sha256 != container_bootstrap_wrapper_artifact_sha256(self)
        ):
            raise ValueError("container bootstrap wrapper artifact is invalid")
        return self


def container_bootstrap_wrapper_artifact_sha256(
    artifact: ContainerBootstrapWrapperArtifactV1,
) -> str:
    """Return the immutable wrapper-artifact commitment without a self-cycle."""

    if type(artifact) is not ContainerBootstrapWrapperArtifactV1:
        raise ValueError("container bootstrap wrapper artifact is invalid")
    payload = artifact.model_copy(update={"artifact_binding_sha256": "0" * 64})
    return _domain_sha256(_WRAPPER_ARTIFACT_DOMAIN, payload)


class ContainerBootstrapWrapperManifestV1(_Model):
    """Separately signed complete wrapper and derived-image manifest."""

    schema_version: Literal["rsd.container-bootstrap-wrapper-manifest.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    attach_protocol_sha256: str = Field(pattern=_SHA256)
    primary_infisical: ContainerBootstrapWrapperArtifactV1
    primary_valkey: ContainerBootstrapWrapperArtifactV1
    restore_infisical: ContainerBootstrapWrapperArtifactV1
    restore_valkey: ContainerBootstrapWrapperArtifactV1
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("created_at")
    @classmethod
    def canonical_created_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def complete_immutable_manifest(self) -> Self:
        artifacts = (
            self.primary_infisical,
            self.primary_valkey,
            self.restore_infisical,
            self.restore_valkey,
        )
        if (
            tuple(item.component for item in artifacts)
            != ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey")
            or any(item.attach_protocol_sha256 != self.attach_protocol_sha256 for item in artifacts)
            or len({item.artifact_binding_sha256 for item in artifacts}) != 4
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("container bootstrap wrapper manifest is invalid")
        return self


def container_bootstrap_wrapper_manifest_sha256(
    manifest: ContainerBootstrapWrapperManifestV1,
) -> str:
    """Return the domain-separated signed-wrapper manifest commitment."""

    if type(manifest) is not ContainerBootstrapWrapperManifestV1:
        raise ValueError("container bootstrap wrapper manifest is invalid")
    return _domain_sha256(_WRAPPER_MANIFEST_DOMAIN, manifest)


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
    image_policy: DockerImagePolicyV1
    entrypoint: tuple[str, ...] = Field(min_length=1, max_length=16)
    command: tuple[str, ...] = Field(default=(), max_length=32)
    entrypoint_sha256: str = Field(pattern=_SHA256)
    template_sha256: str = Field(pattern=_SHA256)
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    wrapper_artifact_binding_sha256: str = Field(pattern=_SHA256)
    attach_protocol_sha256: str = Field(pattern=_SHA256)
    create_request_sha256: str = Field(pattern=_SHA256)
    numeric_user: str = Field(pattern=r"^[1-9][0-9]{0,8}:[1-9][0-9]{0,8}$")
    working_directory: str = Field(pattern=r"^/[A-Za-z0-9._/-]{0,255}$")
    open_stdin: Literal[True]
    stdin_once: Literal[True]
    attach_stdin: Literal[True]
    tty: Literal[False]
    run_as_non_root: Literal[True]
    read_only_root_filesystem: Literal[True]
    cap_drop_all: Literal[True]
    cap_add: tuple[str, ...] = Field(default=(), max_length=0)
    no_new_privileges: Literal[True]
    security_options: tuple[Literal["no-new-privileges:true"],]
    private_pid: Literal[True]
    pid_mode: Literal["isolated_pid_namespace_v1"]
    log_driver: Literal["none"]
    restart_policy: Literal["no"]
    mounts: tuple[DockerNamedVolumeMountV1, ...] = Field(default=(), max_length=1)
    docker_socket_mounted: Literal[False]
    host_network: Literal[False]
    network_mode: Literal["exact_isolated_network_v1"]
    publish_all_ports: Literal[False]
    port_bindings: tuple[str, ...] = Field(default=(), max_length=0)
    labels: tuple[str, ...] = Field(default=(), max_length=0)
    network_name: str = Field(pattern=_IDENTIFIER)
    network_alias: str = Field(pattern=_IDENTIFIER)
    static_ipv4: str
    accepted_secret_sink: ContainerSecretSinkV1

    @field_validator("static_ipv4")
    @classmethod
    def canonical_address(cls, value: str) -> str:
        return _isolated_ipv4(value, field="container bootstrap static IPv4")

    @field_validator(
        "entrypoint",
        "command",
        "cap_add",
        "security_options",
        "mounts",
        "port_bindings",
        "labels",
        mode="before",
    )
    @classmethod
    def declared_sequence(cls, value: object) -> tuple[object, ...]:
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
            or self.image_policy.image != self.image
            or self.entrypoint_sha256
            != _digest(
                json.dumps(self.entrypoint, sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
            or self.entrypoint_sha256 == self.template_sha256
            or len(
                {
                    self.wrapper_manifest_sha256,
                    self.wrapper_artifact_binding_sha256,
                    self.attach_protocol_sha256,
                }
            )
            != 3
            or self.security_options != ("no-new-privileges:true",)
            or self.cap_add != ()
            or self.labels != ()
            or (self.component.endswith("valkey") and len(self.mounts) != 1)
            or (not self.component.endswith("valkey") and self.mounts != ())
            or self.create_request_sha256 != container_create_template_sha256(self)
        ):
            raise ValueError("container bootstrap template is invalid")
        return self


def container_create_template_sha256(template: ContainerBootstrapTemplateV1) -> str:
    """Commit to every canonical Docker create-request field without a cycle."""

    if type(template) is not ContainerBootstrapTemplateV1:
        raise ValueError("container bootstrap template is invalid")
    payload = json.dumps(
        template.model_dump(mode="json", exclude={"create_request_sha256"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _digest(_CREATE_TEMPLATE_DOMAIN + payload)


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
            or len({template.create_request_sha256 for template in templates}) != 4
            or tuple(template.mounts for template in templates[:1] + templates[2:3]) != ((), ())
            or tuple(template.mounts for template in (templates[1], templates[3]))
            != ((templates[1].mounts[0],), (templates[3].mounts[0],))
            or templates[1].mounts[0].source_volume_name
            == templates[3].mounts[0].source_volume_name
        ):
            raise ValueError("container bootstrap templates are invalid")
        return self


class SecretDeliverySinkV1(StrEnum):
    """The exact value-free routes admitted for one provider-material slot."""

    TARGET_DELIVERY_MAP = "signed_target_delivery_map_v1"
    POSTGRESQL_SCRAM_VERIFIER_DERIVATION = "postgresql_scram_verifier_derivation_v1"


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
    target_identities: tuple[str, ...] = Field(min_length=1, max_length=4)

    @field_validator("target_identities", mode="before")
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
                SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                ("primary_infisical", "restore_infisical"),
            ),
            "auth_secret": (
                "infisical_auth_secret_base64_32_v1",
                44,
                SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                ("primary_infisical", "restore_infisical"),
            ),
            "primary_valkey_password": (
                "valkey_password_base64url_32_v1",
                43,
                SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                ("primary_infisical", "primary_valkey"),
            ),
            "restore_valkey_password": (
                "valkey_password_base64url_32_v1",
                43,
                SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                ("restore_infisical", "restore_valkey"),
            ),
            "postgres_application_password": (
                "postgres_application_password_base64url_32_v1",
                43,
                SecretDeliverySinkV1.POSTGRESQL_SCRAM_VERIFIER_DERIVATION,
                (
                    "primary_database",
                    "restore_database",
                    "primary_infisical",
                    "restore_infisical",
                ),
            ),
        }
        if (
            type(self.sink) is not SecretDeliverySinkV1
            or self.target_identities != expected[self.purpose][3]
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
    target_identities: tuple[str, ...] = Field(min_length=1, max_length=4)
    delivered: Literal[True]

    @field_validator("target_identities", mode="before")
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
                SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                ("primary_infisical", "restore_infisical"),
            ),
            "auth_secret": (
                SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                ("primary_infisical", "restore_infisical"),
            ),
            "primary_valkey_password": (
                SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                ("primary_infisical", "primary_valkey"),
            ),
            "restore_valkey_password": (
                SecretDeliverySinkV1.TARGET_DELIVERY_MAP,
                ("restore_infisical", "restore_valkey"),
            ),
            "postgres_application_password": (
                SecretDeliverySinkV1.POSTGRESQL_SCRAM_VERIFIER_DERIVATION,
                (
                    "primary_database",
                    "restore_database",
                    "primary_infisical",
                    "restore_infisical",
                ),
            ),
        }
        if (
            type(self.sink) is not SecretDeliverySinkV1
            or (
                self.sink,
                self.target_identities,
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


class ProviderMaterialFingerprintBindingV1(_Model):
    """One value-free material fingerprint admitted to a target delivery map."""

    purpose: Literal[
        "encryption_key",
        "auth_secret",
        "primary_valkey_password",
        "restore_valkey_password",
        "postgres_application_password",
    ]
    reference_sha256: str = Field(pattern=_SHA256)
    fingerprint_sha256: str = Field(pattern=_SHA256)


class TargetDeliveryValueKindV1(StrEnum):
    """A local attach field is either direct material or a bounded derivation."""

    DIRECT_PROVIDER_MATERIAL = "direct_provider_material_v1"
    DERIVED_POSTGRESQL_URI = "derived_postgresql_uri_v1"
    DERIVED_VALKEY_URI = "derived_valkey_uri_v1"


class TargetDeliveryFieldV1(_Model):
    """One ordered, value-free field sent to an exact target wrapper.

    ``derivation_binding_sha256`` is a grammar commitment, never a hash of a
    raw URI or a secret-bearing result.
    """

    ordinal: int = Field(ge=1, le=4)
    source_purpose: Literal[
        "encryption_key",
        "auth_secret",
        "primary_valkey_password",
        "restore_valkey_password",
        "postgres_application_password",
    ]
    source_reference_sha256: str = Field(pattern=_SHA256)
    source_fingerprint_sha256: str = Field(pattern=_SHA256)
    value_kind: TargetDeliveryValueKindV1
    target_field: Literal[
        "ENCRYPTION_KEY", "AUTH_SECRET", "DB_CONNECTION_URI", "REDIS_URL", "requirepass"
    ]
    format: Literal[
        "infisical_hex_16_v1",
        "infisical_auth_secret_base64_32_v1",
        "valkey_password_base64url_32_v1",
        "derived_postgresql_uri_v1",
        "derived_valkey_uri_v1",
    ]
    encoded_byte_count: int = Field(ge=1, le=1024)
    sink: ContainerSecretSinkV1
    derivation_binding_sha256: str = Field(pattern=_SHA256)
    persistence_allowed: Literal[False]
    logging_allowed: Literal[False]
    receipt_allowed: Literal[False]

    @field_validator("value_kind", mode="before")
    @classmethod
    def canonical_value_kind(cls, value: object) -> TargetDeliveryValueKindV1:
        if type(value) is TargetDeliveryValueKindV1:
            return value
        if type(value) is str:
            try:
                return TargetDeliveryValueKindV1(value)
            except ValueError:
                pass
        raise ValueError("target delivery value kind is invalid")

    @field_validator("sink", mode="before")
    @classmethod
    def canonical_sink(cls, value: object) -> ContainerSecretSinkV1:
        return ContainerBootstrapTemplateV1.canonical_sink(value)


class ContainerTargetDeliveryV1(_Model):
    """One complete target-process or stdin-config delivery route."""

    component: Literal[
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ]
    derived_image_policy_sha256: str = Field(pattern=_SHA256)
    wrapper_artifact_binding_sha256: str = Field(pattern=_SHA256)
    attach_protocol_sha256: str = Field(pattern=_SHA256)
    sink: ContainerSecretSinkV1
    fields: tuple[TargetDeliveryFieldV1, ...] = Field(min_length=1, max_length=4)

    @field_validator("fields", mode="before")
    @classmethod
    def declared_fields(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="target delivery fields")

    @field_validator("sink", mode="before")
    @classmethod
    def canonical_sink(cls, value: object) -> ContainerSecretSinkV1:
        return ContainerBootstrapTemplateV1.canonical_sink(value)

    @model_validator(mode="after")
    def exact_target_route(self) -> Self:
        expected: dict[str, tuple[ContainerSecretSinkV1, tuple[str, ...]]] = {
            "primary_infisical": (
                ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                ("ENCRYPTION_KEY", "AUTH_SECRET", "DB_CONNECTION_URI", "REDIS_URL"),
            ),
            "restore_infisical": (
                ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                ("ENCRYPTION_KEY", "AUTH_SECRET", "DB_CONNECTION_URI", "REDIS_URL"),
            ),
            "primary_valkey": (
                ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
                ("requirepass",),
            ),
            "restore_valkey": (
                ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
                ("requirepass",),
            ),
        }
        if (
            type(self.sink) is not ContainerSecretSinkV1
            or self.sink != expected[self.component][0]
            or tuple(item.ordinal for item in self.fields) != tuple(range(1, len(self.fields) + 1))
            or tuple(item.target_field for item in self.fields) != expected[self.component][1]
            or any(item.sink is not self.sink for item in self.fields)
            or len(
                {
                    self.derived_image_policy_sha256,
                    self.wrapper_artifact_binding_sha256,
                    self.attach_protocol_sha256,
                }
            )
            != 3
        ):
            raise ValueError("container target delivery is invalid")
        return self


class TargetDeliveryMapV1(_Model):
    """Separately signed route map for all four processes and both databases.

    It contains only component identities, exact field grammar, provider
    metadata, and derivation commitments.  It cannot contain a secret,
    verifier, URI, command line, environment mapping, or target file.
    """

    schema_version: Literal["rsd.target-delivery-map.v1"]
    source_commit: str = Field(pattern=_COMMIT)
    allocation_intent_sha256: str = Field(pattern=_SHA256)
    topology: AllocationTopologyV2
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    attach_protocol_sha256: str = Field(pattern=_SHA256)
    secret_handling_policy_sha256: str = Field(pattern=_SHA256)
    provider_references: ProviderReferencesV2
    material_fingerprints: tuple[
        ProviderMaterialFingerprintBindingV1,
        ProviderMaterialFingerprintBindingV1,
        ProviderMaterialFingerprintBindingV1,
        ProviderMaterialFingerprintBindingV1,
        ProviderMaterialFingerprintBindingV1,
    ]
    database_identities: PostgreSQLRuntimeDatabaseIdentitiesV1
    primary_valkey_connection_uri: ValkeyConnectionUriGrammarV1
    restore_valkey_connection_uri: ValkeyConnectionUriGrammarV1
    primary_infisical: ContainerTargetDeliveryV1
    primary_valkey: ContainerTargetDeliveryV1
    restore_infisical: ContainerTargetDeliveryV1
    restore_valkey: ContainerTargetDeliveryV1
    created_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("material_fingerprints", mode="before")
    @classmethod
    def declared_fingerprints(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="target delivery material fingerprints")

    @field_validator("created_at")
    @classmethod
    def canonical_created_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_complete_map(self) -> Self:
        targets = (
            self.primary_infisical,
            self.primary_valkey,
            self.restore_infisical,
            self.restore_valkey,
        )
        fingerprints = self.material_fingerprints
        expected_purposes = (
            "encryption_key",
            "auth_secret",
            "primary_valkey_password",
            "restore_valkey_password",
            "postgres_application_password",
        )
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
        fields = tuple(field for target in targets for field in target.fields)
        expected_source_purposes: dict[str, tuple[str, ...]] = {
            "primary_infisical": (
                "encryption_key",
                "auth_secret",
                "postgres_application_password",
                "primary_valkey_password",
            ),
            "restore_infisical": (
                "encryption_key",
                "auth_secret",
                "postgres_application_password",
                "restore_valkey_password",
            ),
            "primary_valkey": ("primary_valkey_password",),
            "restore_valkey": ("restore_valkey_password",),
        }
        by_component = {str(target.component): target for target in targets}
        primary_uri = self.database_identities.primary_database.connection_uri
        restore_uri = self.database_identities.restore_database.connection_uri
        primary_valkey_uri = self.primary_valkey_connection_uri
        restore_valkey_uri = self.restore_valkey_connection_uri
        topology = self.topology
        fingerprint_by_purpose = {item.purpose: item for item in fingerprints}
        expected_fields: dict[str, tuple[tuple[object, ...], ...]] = {
            "primary_infisical": (
                (
                    "encryption_key",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "infisical_hex_16_v1",
                    32,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    fingerprint_by_purpose.get("encryption_key"),
                ),
                (
                    "auth_secret",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "infisical_auth_secret_base64_32_v1",
                    44,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    fingerprint_by_purpose.get("auth_secret"),
                ),
                (
                    "postgres_application_password",
                    TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
                    "derived_postgresql_uri_v1",
                    primary_uri.rendered_uri_byte_count,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    primary_uri,
                ),
                (
                    "primary_valkey_password",
                    TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
                    "derived_valkey_uri_v1",
                    primary_valkey_uri.rendered_uri_byte_count,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    primary_valkey_uri,
                ),
            ),
            "restore_infisical": (
                (
                    "encryption_key",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "infisical_hex_16_v1",
                    32,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    fingerprint_by_purpose.get("encryption_key"),
                ),
                (
                    "auth_secret",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "infisical_auth_secret_base64_32_v1",
                    44,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    fingerprint_by_purpose.get("auth_secret"),
                ),
                (
                    "postgres_application_password",
                    TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
                    "derived_postgresql_uri_v1",
                    restore_uri.rendered_uri_byte_count,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    restore_uri,
                ),
                (
                    "restore_valkey_password",
                    TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
                    "derived_valkey_uri_v1",
                    restore_valkey_uri.rendered_uri_byte_count,
                    ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                    restore_valkey_uri,
                ),
            ),
            "primary_valkey": (
                (
                    "primary_valkey_password",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "valkey_password_base64url_32_v1",
                    43,
                    ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
                    fingerprint_by_purpose.get("primary_valkey_password"),
                ),
            ),
            "restore_valkey": (
                (
                    "restore_valkey_password",
                    TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                    "valkey_password_base64url_32_v1",
                    43,
                    ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
                    fingerprint_by_purpose.get("restore_valkey_password"),
                ),
            ),
        }

        def field_matches(field: TargetDeliveryFieldV1, expected: tuple[object, ...]) -> bool:
            purpose, value_kind, field_format, byte_count, sink, binding = expected
            if (
                field.source_purpose != purpose
                or field.value_kind is not value_kind
                or field.format != field_format
                or field.encoded_byte_count != byte_count
                or field.sink is not sink
            ):
                return False
            if type(binding) is ProviderMaterialFingerprintBindingV1:
                return (
                    field.source_reference_sha256 == binding.reference_sha256
                    and field.source_fingerprint_sha256 == binding.fingerprint_sha256
                    and field.derivation_binding_sha256 == binding.fingerprint_sha256
                )
            if type(binding) is PostgreSQLConnectionUriGrammarV1:
                return field.derivation_binding_sha256 == runtime_connection_uri_grammar_sha256(
                    binding
                )
            if type(binding) is ValkeyConnectionUriGrammarV1:
                return field.derivation_binding_sha256 == runtime_connection_uri_grammar_sha256(
                    binding
                )
            return False

        if (
            tuple(item.component for item in targets)
            != ("primary_infisical", "primary_valkey", "restore_infisical", "restore_valkey")
            or tuple(item.purpose for item in fingerprints) != expected_purposes
            or len({item.reference_sha256 for item in fingerprints}) != 5
            or len({item.fingerprint_sha256 for item in fingerprints}) != 5
            or any(item.reference_sha256 != references[item.purpose] for item in fingerprints)
            or any(
                tuple(field.source_purpose for field in by_component[component].fields)
                != expected_source_purposes[component]
                for component in expected_source_purposes
            )
            or any(
                field.source_reference_sha256 != references[field.source_purpose]
                for field in fields
            )
            or any(
                field.source_fingerprint_sha256
                != fingerprint_by_purpose[field.source_purpose].fingerprint_sha256
                for field in fields
            )
            or primary_valkey_uri.cache_identity != "primary_valkey"
            or restore_valkey_uri.cache_identity != "restore_valkey"
            or primary_valkey_uri.authority
            != valkey_static_authority(topology.primary_valkey.static_ipv4)
            or restore_valkey_uri.authority
            != valkey_static_authority(topology.restore_valkey.static_ipv4)
            or primary_valkey_uri.password_reference_sha256 != references["primary_valkey_password"]
            or restore_valkey_uri.password_reference_sha256 != references["restore_valkey_password"]
            or any(
                not field_matches(field, expected)
                for component, target in by_component.items()
                for field, expected in zip(target.fields, expected_fields[component], strict=True)
            )
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("target delivery map is invalid")
        return self


def target_delivery_map_sha256(delivery_map: TargetDeliveryMapV1) -> str:
    """Return the signed map commitment used by intents, receipts, and journals."""

    if type(delivery_map) is not TargetDeliveryMapV1:
        raise ValueError("target delivery map is invalid")
    return _domain_sha256(_TARGET_DELIVERY_MAP_DOMAIN, delivery_map)


class ContainerAttachRequestV1(_Model):
    """Value-free metadata preceding one local attach secret stream.

    This request is emitted only after a target wrapper has reached its
    declared readiness state.  Secret chunks are carried separately by the
    local framing codec and never enter this model, its hash, an error, or a
    receipt.
    """

    schema_version: Literal["rsd.container-attach-request.v1"]
    operation_scope: Literal["materialize_and_start_runtime_v1", "start_runtime_v2"]
    operation_id: str = Field(pattern=_UUID)
    component: Literal[
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ]
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    derived_image_policy_sha256: str = Field(pattern=_SHA256)
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    wrapper_artifact_binding_sha256: str = Field(pattern=_SHA256)
    attach_protocol_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    expected_ready_state: Literal["ready_v1"]
    expected_claim_state: Literal["claimed_v1"]
    expected_terminal_ack_state: Literal["terminal_ack_v1"]
    fields: tuple[TargetDeliveryFieldV1, ...] = Field(min_length=1, max_length=4)

    @field_validator("fields", mode="before")
    @classmethod
    def declared_fields(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container attach fields")

    @model_validator(mode="after")
    def bounded_nonsecret_request(self) -> Self:
        if (
            tuple(field.ordinal for field in self.fields) != tuple(range(1, len(self.fields) + 1))
            or len(
                {
                    self.derived_image_policy_sha256,
                    self.wrapper_manifest_sha256,
                    self.wrapper_artifact_binding_sha256,
                    self.attach_protocol_sha256,
                    self.target_delivery_map_sha256,
                    self.request_nonce_sha256,
                    self.channel_binding_sha256,
                    self.session_binding_sha256,
                }
            )
            != 8
        ):
            raise ValueError("container attach request is invalid")
        return self


def container_attach_request_sha256(request: ContainerAttachRequestV1) -> str:
    """Commit one value-free local attach request under its own domain."""

    if type(request) is not ContainerAttachRequestV1:
        raise ValueError("container attach request is invalid")
    return _domain_sha256(_LOCAL_ATTACH_REQUEST_DOMAIN, request)


def container_attach_chunk_descriptors_sha256(
    fields: tuple[TargetDeliveryFieldV1, ...],
) -> str:
    """Commit ordered value-free local-attach chunk descriptors.

    The commitment intentionally covers only the signed descriptor metadata
    (purpose, source fingerprint, grammar, target field, and exact byte
    count).  It never incorporates a delivered value, URI, verifier, or a
    secret-bearing chunk digest.
    """

    if (
        type(fields) is not tuple
        or not 1 <= len(fields) <= 4
        or any(type(field) is not TargetDeliveryFieldV1 for field in fields)
    ):
        raise ValueError("container attach chunk descriptors are invalid")
    try:
        canonical_fields = tuple(
            _strict_canonical_model(field, TargetDeliveryFieldV1) for field in fields
        )
        if tuple(field.ordinal for field in canonical_fields) != tuple(
            range(1, len(canonical_fields) + 1)
        ):
            raise ValueError("container attach chunk descriptors are invalid")
        payload = json.dumps(
            [field.model_dump(mode="json", warnings="error") for field in canonical_fields],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ValueError("container attach chunk descriptors are invalid") from None
    return _digest(_LOCAL_ATTACH_CHUNK_DESCRIPTORS_DOMAIN + payload)


class ContainerAttachReadyV1(_Model):
    """Non-secret wrapper readiness acknowledgement before any chunk is sent."""

    schema_version: Literal["rsd.container-attach-ready.v1"]
    request_sha256: str = Field(pattern=_SHA256)
    component: Literal[
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ]
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: Literal["ready_v1"]
    wrapper_artifact_binding_sha256: str = Field(pattern=_SHA256)
    attach_protocol_sha256: str = Field(pattern=_SHA256)


class ContainerAttachClaimV1(_Model):
    """One local claim immediately before the ordered binary chunks."""

    schema_version: Literal["rsd.container-attach-claim.v1"]
    request_sha256: str = Field(pattern=_SHA256)
    state: Literal["claimed_v1"]
    chunk_count: int = Field(ge=1, le=4)
    chunk_descriptors_sha256: str = Field(pattern=_SHA256)
    eof_required_after_terminal_ack: Literal[True]


class ContainerAttachTerminalAckV1(_Model):
    """Redacted terminal acknowledgement after all ordered chunks are consumed."""

    schema_version: Literal["rsd.container-attach-terminal-ack.v1"]
    request_sha256: str = Field(pattern=_SHA256)
    state: Literal["terminal_ack_v1"]
    chunk_count: int = Field(ge=1, le=4)
    chunk_descriptors_sha256: str = Field(pattern=_SHA256)
    chunks_zeroized: Literal[True]
    persistence_allowed: Literal[False]
    logging_allowed: Literal[False]
    receipt_contains_secret: Literal[False]
    eof_observed: Literal[True]


def container_attach_ack_sha256(ack: ContainerAttachTerminalAckV1) -> str:
    """Return a receipt-safe, domain-separated terminal-ack commitment."""

    if type(ack) is not ContainerAttachTerminalAckV1:
        raise ValueError("container attach terminal acknowledgement is invalid")
    return _domain_sha256(_LOCAL_ATTACH_ACK_DOMAIN, ack)


class ContainerAttachReceiptV1(_Model):
    """Value-free local attach evidence nested in a signed executor receipt.

    The future daemon may attest this record only after its direct local attach
    adapter has observed the complete request/ready/claim/chunk/ack/EOF state
    machine.  It deliberately carries one request commitment and a compact
    completed-state projection rather than duplicating the complete request or
    nested protocol messages.  The outer authorizer reconstructs that request
    from its signed controls and verifies every field below.  No chunk byte,
    URI, verifier, target environment, or raw attach response is representable
    here.
    """

    schema_version: Literal["rsd.container-attach-receipt.v1"]
    request_sha256: str = Field(pattern=_SHA256)
    component: Literal[
        "primary_infisical",
        "primary_valkey",
        "restore_infisical",
        "restore_valkey",
    ]
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    ready_state: Literal["ready_v1"]
    claim_state: Literal["claimed_v1"]
    chunk_count: int = Field(ge=1, le=4)
    chunk_descriptors_sha256: str = Field(pattern=_SHA256)
    terminal_ack_state: Literal["terminal_ack_v1"]
    terminal_ack_sha256: str = Field(pattern=_SHA256)
    chunks_zeroized: Literal[True]
    persistence_allowed: Literal[False]
    logging_allowed: Literal[False]
    receipt_contains_secret: Literal[False]
    eof_observed: Literal[True]

    @model_validator(mode="after")
    def exact_completed_attach_state(self) -> Self:
        invalid = (
            self.chunks_zeroized is not True
            or self.persistence_allowed is not False
            or self.logging_allowed is not False
            or self.receipt_contains_secret is not False
            or self.eof_observed is not True
        )
        if invalid:
            raise ValueError("container attach receipt is invalid")
        try:
            terminal_ack = ContainerAttachTerminalAckV1(
                schema_version="rsd.container-attach-terminal-ack.v1",
                request_sha256=self.request_sha256,
                state=self.terminal_ack_state,
                chunk_count=self.chunk_count,
                chunk_descriptors_sha256=self.chunk_descriptors_sha256,
                chunks_zeroized=self.chunks_zeroized,
                persistence_allowed=self.persistence_allowed,
                logging_allowed=self.logging_allowed,
                receipt_contains_secret=self.receipt_contains_secret,
                eof_observed=self.eof_observed,
            )
        except ValueError:
            raise ValueError("container attach receipt is invalid") from None
        if self.terminal_ack_sha256 != container_attach_ack_sha256(terminal_ack):
            raise ValueError("container attach receipt is invalid")
        return self


def container_attach_receipt_sha256(receipt: ContainerAttachReceiptV1) -> str:
    """Return the receipt-safe local attach completion commitment."""

    if type(receipt) is not ContainerAttachReceiptV1:
        raise ValueError("container attach receipt is invalid")
    return _domain_sha256(_LOCAL_ATTACH_RECEIPT_DOMAIN, receipt)


class MaterializationEvidenceBindingsV1(_Model):
    """Signed chain from allocation observation to the one materialization operation."""

    allocation_intent_sha256: str = Field(pattern=_SHA256)
    allocation_effect_receipt_sha256: str = Field(pattern=_SHA256)
    observed_allocation_attestation_sha256: str = Field(pattern=_SHA256)
    observed_restore_database_attestation_sha256: str = Field(pattern=_SHA256)
    executor_control_policy_sha256: str = Field(pattern=_SHA256)
    docker_engine_control_policy_sha256: str = Field(pattern=_SHA256)
    postgres_prepared_control_policy_sha256: str = Field(pattern=_SHA256)
    executor_installation_policy_sha256: str = Field(pattern=_SHA256)
    executor_installation_intent_sha256: str = Field(pattern=_SHA256)
    executor_installation_receipt_sha256: str = Field(pattern=_SHA256)
    secret_capability_policy_sha256: str = Field(pattern=_SHA256)
    secret_handling_policy_sha256: str = Field(pattern=_SHA256)
    provider_material_attestation_sha256: str = Field(pattern=_SHA256)
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    container_attach_protocol_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def distinct_bindings(self) -> Self:
        if len(set(self.model_dump(mode="python").values())) != 16:
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
    observed_restore_database_attestation_sha256: str = Field(pattern=_SHA256)
    executor_installation_intent_sha256: str = Field(pattern=_SHA256)
    executor_installation_receipt_sha256: str = Field(pattern=_SHA256)
    topology: AllocationTopologyV2
    plan: MaterializationPlanV1
    bootstrap_templates: ContainerBootstrapTemplatesV1
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    container_attach_protocol_sha256: str = Field(pattern=_SHA256)
    postgres_login_transitions: PostgreSQLLoginTransitionIntentsV1
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
            or self.evidence.observed_restore_database_attestation_sha256
            != self.observed_restore_database_attestation_sha256
            or self.evidence.executor_control_policy_sha256
            == self.evidence.secret_capability_policy_sha256
            or self.evidence.docker_engine_control_policy_sha256
            == self.evidence.executor_control_policy_sha256
            or self.evidence.executor_installation_policy_sha256
            == self.evidence.executor_control_policy_sha256
            or self.evidence.executor_installation_intent_sha256
            != self.executor_installation_intent_sha256
            or self.evidence.executor_installation_receipt_sha256
            != self.executor_installation_receipt_sha256
            or any(
                transition.application_password_reference_sha256
                != self.provider_references.postgres_application_password.reference_sha256
                for transition in (
                    self.postgres_login_transitions.primary_database,
                    self.postgres_login_transitions.restore_database,
                )
            )
            or self.postgres_login_transitions.primary_database.system_identifier
            != self.postgres_login_transitions.restore_database.system_identifier
            or len(
                {
                    self.wrapper_manifest_sha256,
                    self.target_delivery_map_sha256,
                    self.container_attach_protocol_sha256,
                }
            )
            != 3
            or self.evidence.wrapper_manifest_sha256 != self.wrapper_manifest_sha256
            or self.evidence.target_delivery_map_sha256 != self.target_delivery_map_sha256
            or self.evidence.container_attach_protocol_sha256
            != self.container_attach_protocol_sha256
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
                or template.image_policy.config_digest_sha256 != component.config_sha256
                or template.network_name != placement.network_name
                or template.network_alias != placement.alias
                or template.static_ipv4 != placement.static_ipv4
                for component, placement, template in zip(
                    components, (item[1] for item in expected), templates, strict=True
                )
            )
            or len({component.config_sha256 for component in components}) != 4
            or self.bootstrap_templates.primary_valkey.mounts[0].source_volume_name
            != self.plan.primary_valkey.volume_name
            or self.bootstrap_templates.restore_valkey.mounts[0].source_volume_name
            != self.plan.restore_valkey.volume_name
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

    image_policy_binding: DockerImagePolicyBindingV1
    entrypoint: tuple[str, ...] = Field(min_length=1, max_length=16)
    command: tuple[str, ...] = Field(default=(), max_length=32)
    entrypoint_sha256: str = Field(pattern=_SHA256)
    template_sha256: str = Field(pattern=_SHA256)
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    wrapper_artifact_binding_sha256: str = Field(pattern=_SHA256)
    attach_protocol_sha256: str = Field(pattern=_SHA256)
    create_request_sha256: str = Field(pattern=_SHA256)
    numeric_user: str = Field(pattern=r"^[1-9][0-9]{0,8}:[1-9][0-9]{0,8}$")
    working_directory: str = Field(pattern=r"^/[A-Za-z0-9._/-]{0,255}$")
    open_stdin: Literal[True]
    stdin_once: Literal[True]
    attach_stdin: Literal[True]
    tty: Literal[False]
    run_as_non_root: Literal[True]
    read_only_root_filesystem: Literal[True]
    cap_drop_all: Literal[True]
    cap_add: tuple[str, ...] = Field(default=(), max_length=0)
    no_new_privileges: Literal[True]
    security_options: tuple[Literal["no-new-privileges:true"],]
    private_pid: Literal[True]
    pid_mode: Literal["isolated_pid_namespace_v1"]
    log_driver: Literal["none"]
    restart_policy: Literal["no"]
    mounts: tuple[DockerNamedVolumeMountV1, ...] = Field(default=(), max_length=1)
    docker_socket_mounted: Literal[False]
    host_network: Literal[False]
    network_mode: Literal["exact_isolated_network_v1"]
    publish_all_ports: Literal[False]
    port_bindings: tuple[str, ...] = Field(default=(), max_length=0)
    labels: tuple[str, ...] = Field(default=(), max_length=0)
    network_name: str = Field(pattern=_IDENTIFIER)
    network_alias: str = Field(pattern=_IDENTIFIER)
    static_ipv4: str
    accepted_secret_sink: ContainerSecretSinkV1
    running: Literal[True]

    @field_validator("static_ipv4")
    @classmethod
    def canonical_address(cls, value: str) -> str:
        return _isolated_ipv4(value, field="container inspection static IPv4")

    @field_validator(
        "entrypoint",
        "command",
        "cap_add",
        "security_options",
        "mounts",
        "port_bindings",
        "labels",
        mode="before",
    )
    @classmethod
    def declared_sequence(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container inspection sequence")

    @field_validator("accepted_secret_sink", mode="before")
    @classmethod
    def canonical_sink(cls, value: object) -> ContainerSecretSinkV1:
        return ContainerBootstrapTemplateV1.canonical_sink(value)

    @model_validator(mode="after")
    def distinct_template_fields(self) -> Self:
        if (
            self.entrypoint_sha256
            != _digest(
                json.dumps(self.entrypoint, sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
            or self.entrypoint_sha256 == self.template_sha256
            or len(
                {
                    self.wrapper_manifest_sha256,
                    self.wrapper_artifact_binding_sha256,
                    self.attach_protocol_sha256,
                }
            )
            != 3
            or self.security_options != ("no-new-privileges:true",)
            or self.cap_add != ()
            or self.labels != ()
        ):
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
    image: ImageReferenceV1
    config_sha256: str = Field(pattern=_SHA256)
    image_policy_binding: DockerImagePolicyBindingV1
    attachments: tuple[RuntimeNetworkAttachmentV1, ...] = Field(min_length=1, max_length=1)
    no_host_publication: NoHostPublicationEvidenceV1
    inspection: ContainerBootstrapInspectionV1

    @field_validator("attachments", mode="before")
    @classmethod
    def declared_attachments(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="runtime attachments")

    @model_validator(mode="after")
    def image_chain_is_explicit(self) -> Self:
        if (
            self.image_policy_binding.image != self.image
            or self.image_policy_binding.config_digest_sha256 != self.config_sha256
        ):
            raise ValueError("runtime image identity is invalid")
        return self


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
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    container_attach_protocol_sha256: str = Field(pattern=_SHA256)
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
    attach_receipt: ContainerAttachReceiptV1
    attach_receipt_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def exact_local_attach_evidence(self) -> Self:
        if (
            self.attach_receipt_sha256 != container_attach_receipt_sha256(self.attach_receipt)
            or self.attach_receipt.component != self.component
            or self.attach_receipt.container_id != self.container_id
        ):
            raise ValueError("executor container attach evidence is invalid")
        return self


class MaterializationExecutorReceiptV1(_Model):
    """Executor-attested, redacted materialization inspection result."""

    schema_version: Literal["rsd.materialization-executor-receipt.v1"]
    executor_id: str = Field(pattern=_IDENTIFIER)
    installation_receipt_sha256: str = Field(pattern=_SHA256)
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    container_attach_protocol_sha256: str = Field(pattern=_SHA256)
    operation_scope: Literal["materialize_and_start_runtime_v1"]
    operation_id: str = Field(pattern=_UUID)
    idempotency_key: str = Field(pattern=_SHA256)
    materialization_intent_sha256: str = Field(pattern=_SHA256)
    observed_allocation_attestation_sha256: str = Field(pattern=_SHA256)
    docker_engine_control_policy_sha256: str = Field(pattern=_SHA256)
    secret_delivery_receipt_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    host_fingerprint_sha256: str = Field(pattern=_SHA256)
    engine_fingerprint_sha256: str = Field(pattern=_SHA256)
    engine_operation_journal_sha256: str = Field(pattern=_SHA256)
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
            or len(
                {
                    self.wrapper_manifest_sha256,
                    self.target_delivery_map_sha256,
                    self.container_attach_protocol_sha256,
                }
            )
            != 3
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("executor operation receipt is invalid")
        return self


def materialization_executor_receipt_message(receipt: MaterializationExecutorReceiptV1) -> bytes:
    """Return the exact attestation preimage for materialization evidence."""

    receipt = _strict_canonical_model(receipt, MaterializationExecutorReceiptV1)
    return _executor_receipt_message(_MATERIALIZATION_EXECUTOR_RECEIPT_DOMAIN, receipt)


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
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    container_attach_protocol_sha256: str = Field(pattern=_SHA256)
    executor_receipt_sha256: str = Field(pattern=_SHA256)
    executor_receipt: MaterializationExecutorReceiptV1
    postgres_login_transitions: PostgreSQLLoginTransitionReceiptsV1
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
            or self.executor_receipt_sha256 != canonical_sha256(self.executor_receipt)
            or self.executor_receipt.secret_delivery_receipt_sha256
            != canonical_sha256(self.delivery_receipt)
            or self.executor_receipt.wrapper_manifest_sha256 != self.wrapper_manifest_sha256
            or self.executor_receipt.target_delivery_map_sha256 != self.target_delivery_map_sha256
            or self.executor_receipt.container_attach_protocol_sha256
            != self.container_attach_protocol_sha256
            or len(
                {
                    self.wrapper_manifest_sha256,
                    self.target_delivery_map_sha256,
                    self.container_attach_protocol_sha256,
                }
            )
            != 3
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
    observed_restore_database_attestation_sha256: str = Field(pattern=_SHA256)
    executor_control_policy_sha256: str = Field(pattern=_SHA256)
    executor_installation_policy_sha256: str = Field(pattern=_SHA256)
    executor_installation_intent_sha256: str = Field(pattern=_SHA256)
    executor_installation_receipt_sha256: str = Field(pattern=_SHA256)
    secret_capability_policy_sha256: str = Field(pattern=_SHA256)
    secret_handling_policy_sha256: str = Field(pattern=_SHA256)
    provider_material_attestation_sha256: str = Field(pattern=_SHA256)
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    container_attach_protocol_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def distinct_bindings(self) -> Self:
        if len(set(self.model_dump(mode="python").values())) != 14:
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
    observed_restore_database_attestation_sha256: str = Field(pattern=_SHA256)
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
            or self.evidence.observed_restore_database_attestation_sha256
            != self.observed_restore_database_attestation_sha256
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
    engine_operation_journal_sha256: str = Field(pattern=_SHA256)
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    container_attach_protocol_sha256: str = Field(pattern=_SHA256)
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
            or len(
                {
                    self.wrapper_manifest_sha256,
                    self.target_delivery_map_sha256,
                    self.container_attach_protocol_sha256,
                }
            )
            != 3
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
        ):
            raise ValueError("start executor receipt is invalid")
        return self


def start_runtime_executor_receipt_message(receipt: StartRuntimeExecutorReceiptV2) -> bytes:
    """Return the exact attestation preimage for one fresh runtime start."""

    receipt = _strict_canonical_model(receipt, StartRuntimeExecutorReceiptV2)
    return _executor_receipt_message(_START_RUNTIME_EXECUTOR_RECEIPT_DOMAIN, receipt)


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
    wrapper_manifest_sha256: str = Field(pattern=_SHA256)
    target_delivery_map_sha256: str = Field(pattern=_SHA256)
    container_attach_protocol_sha256: str = Field(pattern=_SHA256)
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
            or executor.wrapper_manifest_sha256 != self.wrapper_manifest_sha256
            or executor.target_delivery_map_sha256 != self.target_delivery_map_sha256
            or executor.container_attach_protocol_sha256 != self.container_attach_protocol_sha256
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
    if (
        type(observed.attachments) is not tuple
        or len(observed.attachments) != 1
        or type(observed.attachments[0]) is not RuntimeNetworkAttachmentV1
    ):
        return False
    attachment = observed.attachments[0]
    return (
        observed.container_id == candidate.container_id
        and observed.image == candidate.image
        and attachment.network_name == candidate.network_name
        and attachment.network_id == candidate.network_id
    )


def _matches_runtime_topology(
    observed: RuntimeContainerObservationV1,
    *,
    placement: ComponentPlacementV1,
    network_id: str,
) -> bool:
    """Require every inspected attachment field, not just network identity."""

    if (
        type(observed.attachments) is not tuple
        or len(observed.attachments) != 1
        or type(observed.attachments[0]) is not RuntimeNetworkAttachmentV1
    ):
        return False
    attachment = observed.attachments[0]
    return (
        attachment.network_name == placement.network_name
        and attachment.network_id == network_id
        and attachment.alias == placement.alias
        and attachment.static_ipv4 == placement.static_ipv4
    )


def validate_observed_runtime_transition(
    allocation: ObservedAllocationAttestationV1,
    restore_database: ObservedRestoreDatabaseAttestationV1,
    intent: MaterializationIntentV1,
    receipt: MaterializationEffectReceiptV1,
    attestation: ObservedRuntimeAttestationV1,
    proposal: ProposalV1,
    contract: RuntimeContractV1,
) -> None:
    """Require the full V2 allocation/materialization chain before observed effects."""

    if (
        type(allocation) is not ObservedAllocationAttestationV1
        or type(restore_database) is not ObservedRestoreDatabaseAttestationV1
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
        or intent.observed_restore_database_attestation_sha256
        != observed_restore_database_attestation_sha256(restore_database)
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
        or not _matches_runtime_topology(
            receipt.primary_infisical,
            placement=intent.topology.primary_infisical,
            network_id=allocation.allocated_resources.primary_network.network_id,
        )
        or not _matches_runtime_topology(
            receipt.primary_valkey,
            placement=intent.topology.primary_valkey,
            network_id=allocation.allocated_resources.primary_network.network_id,
        )
        or not _matches_runtime_topology(
            receipt.restore_infisical,
            placement=intent.topology.restore_infisical,
            network_id=allocation.allocated_resources.restore_network.network_id,
        )
        or not _matches_runtime_topology(
            receipt.restore_valkey,
            placement=intent.topology.restore_valkey,
            network_id=allocation.allocated_resources.restore_network.network_id,
        )
        or allocation.allocated_resources.postgres.system_identifier
        != proposal.candidate.postgres.system_identifier
        or allocation.allocated_resources.postgres.database_oid
        != proposal.candidate.postgres.database_oid
        or intent.postgres_login_transitions.primary_database.schema_oid
        != allocation.allocated_resources.postgres.schema_oid
        or intent.postgres_login_transitions.restore_database.schema_oid
        != restore_database.restore_database.schema_oid
        or receipt.postgres_login_transitions.primary_database.schema_oid
        != intent.postgres_login_transitions.primary_database.schema_oid
        or receipt.postgres_login_transitions.restore_database.schema_oid
        != intent.postgres_login_transitions.restore_database.schema_oid
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
