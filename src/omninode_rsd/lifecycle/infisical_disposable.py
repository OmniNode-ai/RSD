"""Offline Phase-A evidence compiler for a disposable Infisical acceptance lane.

The module performs no network, container, database, provider, or receipt write
operation.  It compiles value-free, owner-only artifacts into a non-authorizing
receipt; a separately authorized runtime must verify signatures and live
provenance before it can perform any action.
"""

from __future__ import annotations

import argparse
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
    owner_role: str = Field(pattern=_IDENTIFIER)
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
        return self


class TransportContractV1(_Model):
    profile: DisposableTransportProfile
    authority: str
    authority_sha256: str = Field(pattern=_SHA256)
    listener_binding: Literal["tls_lan", "loopback_only", "isolated_network_only"]
    host_listener_port: int | None = Field(default=None, ge=1, le=65535)
    isolated_network_id: str | None = Field(default=None, pattern=_IDENTIFIER)
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
        if self.profile is DisposableTransportProfile.TLS_VERIFIED:
            valid = (
                parsed.scheme == "https"
                and self.listener_binding == "tls_lan"
                and self.host_listener_port == parsed.port
                and self.isolated_network_id is None
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
                        and self.isolated_network_id is None
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
                        and self.isolated_network_id is not None
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
    network_id: str = Field(pattern=_IDENTIFIER)
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    workload_id: str = Field(pattern=_IDENTIFIER)
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
    network_id: str = Field(pattern=_IDENTIFIER)
    volume_id: str = Field(pattern=_IDENTIFIER)
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    workload_id: str = Field(pattern=_IDENTIFIER)
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
        if (
            len({item.volume_id for item in caches}) != 2
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
            primary.network_id != self.transport.isolated_network_id
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
        if self.transport.profile is DisposableTransportProfile.TLS_VERIFIED:
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
    """Descriptor-relative reader for bounded, owner-only regular files."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._uid = os.getuid()

    def _root_fd(self) -> int:
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


def compile_preflight(paths: PreflightPaths, *, now: datetime | None = None) -> PreflightReceiptV1:
    """Compile Phase-A artifacts and return a non-authorizing receipt in memory."""

    clock = datetime.now(UTC) if now is None else now
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise DisposablePreflightError("clock")
    reader = _OwnerOnlyReader(paths.root)
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
