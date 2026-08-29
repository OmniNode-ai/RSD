"""Effect-free V4 allocation-parameterized, wrapper-output-independent inputs.

V4 deliberately separates a compiled role's static inputs from the signed
``TargetDeliveryMapV1`` envelope.  Its projection carries only the target
delivery grammar needed by a future wrapper: four ordered field routes and
their value-free URI grammars.  It intentionally carries no allocation
topology, V1 map hash, wrapper manifest, artifact binding, derived image, OCI
result, signature, receipt, or effect result.  A future closure must
independently verify the signed V1 map and prove its exact relation to this
many-to-one, non-authorizing projection.

Exact URI authorities and static delivery grammar are allocation-parameterized
inputs needed before target URI construction.  They are not wrapper-output
evidence: V4 carries no artifact/image/manifest/OCI build result and cannot
close that fixed point.  A later allocation closure must authenticate those
inputs and their relation to observed topology.

This module has no frame reader, secret carrier, provider access, Engine
client, filesystem access, runtime adapter, replay-persistence adapter, or
effect API.  It defines only canonical metadata, signature checks, a
non-authorizing future-claim intent, and repeatable receipt validation.  A
peer-authenticated executor capability and durable one-shot redemption remain
required before any delivery could be considered.  The raw frame codec and
every build, artifact, manifest, inspection, authorization, and evidence
binding remain deliberately unimplemented.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import math
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Literal, NoReturn, Self, cast
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerAttachTicketTrustAnchorV1,
    ContainerBootstrapEnvironmentConstructionPolicyV2,
    ContainerBootstrapFdPolicyV2,
    ContainerBootstrapMemorySafetyPolicyV2,
    ContainerBootstrapPid1PolicyV2,
    ContainerBootstrapStaticEnvironmentEntryV2,
    ContainerBootstrapStaticEnvironmentV2,
    ContainerBootstrapValkeyLaunchPolicyV2,
    ContainerSecretSinkV1,
    ContainerTargetDeliveryV1,
    PostgreSQLConnectionUriGrammarV1,
    TargetDeliveryFieldV1,
    TargetDeliveryMapV1,
    TargetDeliveryValueKindV1,
    ValkeyConnectionUriGrammarV1,
    container_bootstrap_environment_construction_policy_sha256,
    container_bootstrap_valkey_static_configuration_sha256,
    postgresql_connection_uri_rendered_byte_count,
    runtime_connection_uri_grammar_sha256,
    valkey_connection_uri_rendered_byte_count,
    valkey_static_authority,
)

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_UUID = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CONTAINER_ID = r"^[0-9a-f]{64}$"
_HOSTNAME = r"^[a-z0-9][a-z0-9-]{14,61}[a-z0-9]$"
_STATIC_PATH = r"^/[A-Za-z0-9._/-]{1,240}$"
_STATIC_ARG = r"^[A-Za-z0-9._/:=@+,%=-]{1,256}$"
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
# V4 profiles cap all variable-size source inputs (including 64 argv tokens
# per launch vector) at 256 KiB. A signed envelope adds at most 8 KiB of
# bounded identity data. A complete non-authorizing claim intent carries one
# such envelope plus a bounded target ticket and fixed replay metadata; its
# separate 512 KiB limit is therefore finite and admits every V4 model accepted
# by the canonical shape validator below.  No V4 authority call exists.
_MAX_STATIC_CANONICAL_BYTES = 262_144
_MAX_PROFILE_ENVELOPE_CANONICAL_BYTES = 270_336
_MAX_CLAIM_INTENT_BYTES = 524_288
_MAX_ATTACH_METADATA_BYTES = 16_384
_MAX_CANONICAL_JSON_DEPTH = 32
_MAX_CANONICAL_JSON_NODES = 4_096
# The launch plan is an upstream input to the isolated artifact-evidence
# verifier.  Keep these limits explicit here so direct construction and the
# canonical parser share one closed domain.  The byte total is deliberately
# the full 64 * 256 legal vector, not a narrower downstream eligibility rule.
_MAX_STATIC_ARG_ITEMS = 64
_MAX_STATIC_ARG_BYTES = 256
_MAX_STATIC_ARG_VECTOR_BYTES = _MAX_STATIC_ARG_ITEMS * _MAX_STATIC_ARG_BYTES

_STATIC_PROJECTION_DOMAIN = (
    b"omninode-rsd.container-bootstrap-static-delivery-projection.sha256.v4\x00"
)
_STATIC_ROUTE_DOMAIN = b"omninode-rsd.container-bootstrap-static-delivery-route.sha256.v4\x00"
_STATIC_FIELD_DOMAIN = b"omninode-rsd.container-bootstrap-static-delivery-field.sha256.v4\x00"
_STATIC_URI_GRAMMAR_DOMAIN = b"omninode-rsd.container-bootstrap-static-uri-grammar.sha256.v4\x00"
_STATIC_LAUNCH_PLAN_DOMAIN = b"omninode-rsd.container-bootstrap-static-launch-plan.sha256.v4\x00"
_STATIC_PATCH_PREIMAGE_DOMAIN = (
    b"omninode-rsd.container-bootstrap-static-patch-preimage.sha256.v4\x00"
)
_STATIC_PATCH_POLICY_DOMAIN = b"omninode-rsd.container-bootstrap-static-patch-policy.sha256.v4\x00"
_STATIC_VALKEY_LAUNCH_POLICY_DOMAIN = (
    b"omninode-rsd.container-bootstrap-static-valkey-launch-policy.sha256.v4\x00"
)
_STATIC_MERGED_ARGV_DOMAIN = b"omninode-rsd.container-bootstrap-static-merged-argv.sha256.v4\x00"
_STATIC_PROFILE_DOMAIN = b"omninode-rsd.container-bootstrap-static-role-profile.sha256.v4\x00"
_STATIC_PROFILE_ENVELOPE_DOMAIN = (
    b"omninode-rsd.container-bootstrap-static-role-profile-envelope.ed25519.v4\x00"
)
_STATIC_PROFILE_ENVELOPE_HASH_DOMAIN = (
    b"omninode-rsd.container-bootstrap-static-role-profile-envelope.sha256.v4\x00"
)
_ATTACH_PROTOCOL_DOMAIN = b"omninode-rsd.container-bootstrap-attach-protocol.sha256.v4\x00"
_ATTACH_REQUEST_DOMAIN = b"omninode-rsd.container-attach-request.sha256.v4\x00"
_ATTACH_TICKET_DOMAIN = b"omninode-rsd.container-attach-ticket.ed25519.v4\x00"
_ATTACH_TICKET_HASH_DOMAIN = b"omninode-rsd.container-attach-ticket.sha256.v4\x00"
_RUNTIME_BINDING_DOMAIN = b"omninode-rsd.container-attach-runtime-binding.sha256.v4\x00"
_TICKET_REPLAY_CLAIM_DOMAIN = b"omninode-rsd.container-attach-ticket-replay-claim.sha256.v4\x00"
_CONTAINER_LIFETIME_CLAIM_DOMAIN = (
    b"omninode-rsd.container-attach-container-lifetime-claim.sha256.v4\x00"
)
_REPLAY_CLAIM_DOMAIN = b"omninode-rsd.container-attach-replay-claim.sha256.v4\x00"
_REPLAY_PREPARATION_DOMAIN = b"omninode-rsd.container-attach-claim-preparation.sha256.v4\x00"
_REPLAY_RECEIPT_DOMAIN = b"omninode-rsd.container-attach-replay-receipt.ed25519.v4\x00"

_ComponentV4 = Literal[
    "primary_infisical",
    "primary_valkey",
    "restore_infisical",
    "restore_valkey",
]
_OperationScopeV4 = Literal["materialize_and_start_runtime_v1", "start_runtime_v2"]
_COMPONENTS: tuple[_ComponentV4, _ComponentV4, _ComponentV4, _ComponentV4] = (
    "primary_infisical",
    "primary_valkey",
    "restore_infisical",
    "restore_valkey",
)


class ContainerAttachStaticV4Error(ValueError):
    """A fixed, value-free V4 static-contract verification failure."""

    __slots__ = ("phase",)

    def __init__(
        self,
        phase: Literal[
            "projection", "profile", "ticket", "signature", "freshness", "binding", "replay"
        ],
    ) -> None:
        super().__init__("container attach V4 verification failed")
        self.phase = phase


class _Model(BaseModel):
    """Strict immutable V4 public metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def _fail(
    phase: Literal[
        "projection", "profile", "ticket", "signature", "freshness", "binding", "replay"
    ],
) -> NoReturn:
    """Raise after a collaborator scope without preserving its exception chain."""

    raise ContainerAttachStaticV4Error(phase)


def _items(value: object, *, field: str) -> tuple[object, ...]:
    """Accept only an exact immutable tuple at a V4 static boundary."""

    if type(value) is not tuple:
        raise ValueError(f"{field} must be a tuple")
    return value


def _canonical_base64_bytes(value: str) -> bytes:
    """Decode one exact standard-base64 spelling without aliases."""

    if type(value) is not str:
        raise ValueError("base64 value is invalid")
    raw: bytes | None = None
    try:
        encoded = value.encode("ascii")
        raw = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raw = None
    if raw is None or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("base64 value is invalid")
    return raw


def _canonical_timestamp(value: str) -> datetime:
    """Parse the one UTC timestamp spelling used by V4 tickets."""

    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise ValueError("ticket timestamp is invalid")
    parsed: datetime | None = None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        parsed = None
    if parsed is None:
        raise ValueError("ticket timestamp is invalid")
    return parsed


def _canonical_timestamp_text(value: datetime) -> str:
    """Render the exact second-granularity UTC timestamp spelling."""

    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond != 0
    ):
        raise ValueError("ticket timestamp is invalid")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_model_bytes(model: BaseModel, *, exclude: set[str] | None = None) -> bytes:
    """Render a strict model as canonical ASCII-safe JSON."""

    payload: object | None = None
    try:
        payload = model.model_dump(mode="json", exclude=exclude or set(), warnings="error")
    except (RecursionError, TypeError, ValueError):
        payload = None
    if payload is None:
        raise ValueError("canonical model is invalid")
    rendered: str | None = None
    try:
        rendered = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (RecursionError, TypeError, ValueError):
        rendered = None
    if rendered is None:
        raise ValueError("canonical model is invalid")
    return rendered.encode("ascii")


def _no_duplicate_json_object(pairs: list[tuple[object, object]]) -> dict[str, object]:
    """Build one JSON object while rejecting duplicate or non-string keys."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("canonical JSON object is invalid")
        result[key] = value
    return result


def _json_arrays_as_tuples(
    value: object,
    *,
    depth: int = 0,
    nodes: list[int] | None = None,
) -> object:
    """Bound and translate JSON's mutable sequence shape into immutable tuples."""

    if depth > _MAX_CANONICAL_JSON_DEPTH:
        raise ValueError("canonical JSON is invalid")
    node_count = nodes if nodes is not None else [0]
    node_count[0] += 1
    if node_count[0] > _MAX_CANONICAL_JSON_NODES:
        raise ValueError("canonical JSON is invalid")
    if type(value) is list:
        return tuple(
            _json_arrays_as_tuples(item, depth=depth + 1, nodes=node_count) for item in value
        )
    if type(value) is dict:
        return {
            key: _json_arrays_as_tuples(item, depth=depth + 1, nodes=node_count)
            for key, item in value.items()
        }
    return value


def _hash(domain: bytes, model: BaseModel, *, exclude: set[str] | None = None) -> str:
    """Hash one canonical model under an explicit V4 domain."""

    return hashlib.sha256(domain + _canonical_model_bytes(model, exclude=exclude)).hexdigest()


def _expected_role(component: str) -> Literal["infisical", "valkey"]:
    """Return the fixed role for one of the four V4 components."""

    return "valkey" if component.endswith("valkey") else "infisical"


def _trusted_utc_now() -> datetime:
    """Read production UTC at a V4 ticket verification boundary."""

    return datetime.now(UTC).replace(microsecond=0)


def _trusted_monotonic_now() -> float:
    """Read production monotonic time for one bounded replay-authority call."""

    return time.monotonic()


def _valid_monotonic(value: object) -> bool:
    """Accept only exact finite nonnegative monotonic-clock observations."""

    return type(value) is float and math.isfinite(value) and value >= 0.0


def _trusted_now() -> datetime:
    """Read exact trusted UTC or fail closed without a clock cause chain."""

    now: datetime | None = None
    try:
        candidate = _trusted_utc_now()
        if (
            type(candidate) is datetime
            and candidate.tzinfo is not None
            and candidate.utcoffset() == timedelta(0)
        ):
            now = candidate.replace(microsecond=0)
    except Exception:
        now = None
    if now is None:
        _fail("freshness")
    return now


def _read_trusted_monotonic_now() -> float:
    """Read one finite monotonic value through the module-local boundary."""

    now: float | None = None
    try:
        candidate = _trusted_monotonic_now()
        if _valid_monotonic(candidate):
            now = candidate
    except Exception:
        now = None
    if now is None:
        _fail("freshness")
    return now


def _strict_canonical_model[T: _Model](value: T, expected: type[T]) -> T:
    """Round-trip an exact concrete model after recursive type-tree checking."""

    if type(value) is not expected:
        raise ValueError("canonical model is invalid")
    _assert_exact_concrete_tree(value, expected)
    canonical: T | None = None
    try:
        canonical = expected.model_validate(value.model_dump(mode="python", warnings="error"))
    except (RecursionError, TypeError, ValueError):
        canonical = None
    if canonical is None or type(canonical) is not expected or canonical != value:
        raise ValueError("canonical model is invalid")
    return canonical


def _preflight_canonical_json_structure(payload: bytes) -> None:
    """Bound JSON nesting and lexical nodes before allocating a parsed tree.

    This deliberately conservative scanner counts every container, string,
    and scalar token (including object keys), so its count is an upper bound
    on the nodes later traversed by :func:`_json_arrays_as_tuples`.  It is not
    a JSON parser: the standard parser still validates grammar and escapes.
    Keeping the structural limit before ``json.loads`` prevents a valid-size
    but deeply nested or token-dense payload from reaching recursive model
    validation first.
    """

    depth = 0
    nodes = 0
    index = 0
    in_string = False
    escaped = False
    length = len(payload)
    while index < length:
        character = payload[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == 0x5C:  # ``\\``
                escaped = True
            elif character == 0x22:  # ``\"``
                in_string = False
            elif character < 0x20:
                raise ValueError("canonical JSON is invalid")
            index += 1
            continue
        if character in b" \t\r\n:,":
            index += 1
            continue
        if character == 0x22:  # ``\"``
            nodes += 1
            in_string = True
        elif character in b"{[":
            nodes += 1
            depth += 1
            if depth > _MAX_CANONICAL_JSON_DEPTH:
                raise ValueError("canonical JSON is invalid")
        elif character in b"}]":
            depth -= 1
            if depth < 0:
                raise ValueError("canonical JSON is invalid")
        else:
            # One unquoted lexical unit can only become one JSON scalar if
            # grammar validation accepts it.  Skip it here so digits in a
            # number or letters in a literal cannot inflate the node count.
            nodes += 1
            while index < length and payload[index] not in b" \t\r\n,]}":
                index += 1
            index -= 1
        if nodes > _MAX_CANONICAL_JSON_NODES:
            raise ValueError("canonical JSON is invalid")
        index += 1
    if in_string or escaped or depth != 0:
        raise ValueError("canonical JSON is invalid")


def _parse_canonical_json[T: _Model](
    payload: bytes,
    expected: type[T],
    *,
    max_bytes: int = _MAX_STATIC_CANONICAL_BYTES,
) -> T:
    """Parse exact canonical JSON while rejecting duplicate keys and aliases."""

    if (
        type(payload) is not bytes
        or type(max_bytes) is not int
        or not 1 <= max_bytes <= _MAX_CLAIM_INTENT_BYTES
        or not 1 <= len(payload) <= max_bytes
    ):
        raise ValueError("canonical JSON is invalid")
    _preflight_canonical_json_structure(payload)
    decoded: object | None = None
    try:
        decoded = json.loads(payload.decode("ascii"), object_pairs_hook=_no_duplicate_json_object)
    except (RecursionError, UnicodeDecodeError, TypeError, ValueError):
        decoded = None
    if type(decoded) is not dict:
        raise ValueError("canonical JSON is invalid")
    model: T | None = None
    try:
        model = expected.model_validate(_json_arrays_as_tuples(decoded))
        model = _strict_canonical_model(model, expected)
    except (RecursionError, TypeError, ValueError):
        model = None
    canonical: bytes | None = None
    try:
        if model is not None:
            canonical = _canonical_model_bytes(model)
    except (RecursionError, TypeError, ValueError):
        canonical = None
    if model is None or canonical != payload:
        raise ValueError("canonical JSON is invalid")
    return model


def _canonical_uri_authority_v4(value: str, *, scheme: Literal["postgresql", "redis"]) -> str:
    """Validate one canonical literal-IP authority without rendering a URI value."""

    if type(value) is not str or any(character.isspace() for character in value):
        raise ValueError("container bootstrap V4 URI authority is invalid")
    parsed = None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        port = None
    if (
        parsed is None
        or parsed.scheme != scheme
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port is None
    ):
        raise ValueError("container bootstrap V4 URI authority is invalid")
    host = None
    try:
        host = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        host = None
    if host is None:
        raise ValueError("container bootstrap V4 URI authority is invalid")
    rendered_host = f"[{host.compressed}]" if host.version == 6 else host.compressed
    if value != f"{scheme}://{rendered_host}:{port}":
        raise ValueError("container bootstrap V4 URI authority is invalid")
    return value


class ContainerBootstrapStaticPostgreSQLUriGrammarV4(_Model):
    """Output-independent target URI grammar with no observed operation identity.

    This is a fresh V4 projection of a V1 grammar.  In particular it excludes
    V1's ``prepared_operation_id``: that observed-operation binding belongs to
    the later signed V1-map-to-V4-projection closure, not to compiled static
    target input.  It still commits every value-free fact needed to construct
    the target-only PostgreSQL URI.
    """

    schema_version: Literal["rsd.container-bootstrap-static-postgresql-uri-grammar.v4"]
    database_identity: Literal["primary_database", "restore_database"]
    authority: str
    database_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
    application_role: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
    application_password_reference_sha256: str = Field(pattern=_SHA256)
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
    def canonical_authority(cls, value: str) -> str:
        return _canonical_uri_authority_v4(value, scheme="postgresql")

    @model_validator(mode="after")
    def exact_target_grammar(self) -> Self:
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
            raise ValueError("container bootstrap V4 PostgreSQL URI grammar is invalid")
        return self


class ContainerBootstrapStaticValkeyUriGrammarV4(_Model):
    """Output-independent target Valkey URI grammar for one Infisical role."""

    schema_version: Literal["rsd.container-bootstrap-static-valkey-uri-grammar.v4"]
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
    def canonical_authority(cls, value: str) -> str:
        return _canonical_uri_authority_v4(value, scheme="redis")

    @model_validator(mode="after")
    def exact_target_grammar(self) -> Self:
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
            raise ValueError("container bootstrap V4 Valkey URI grammar is invalid")
        return self


_StaticUriGrammarV4 = (
    ContainerBootstrapStaticPostgreSQLUriGrammarV4 | ContainerBootstrapStaticValkeyUriGrammarV4
)


def container_bootstrap_static_uri_grammar_v4_sha256(grammar: _StaticUriGrammarV4) -> str:
    """Hash one exact output-independent V4 target URI grammar."""

    expected: type[_Model] | None = None
    if type(grammar) is ContainerBootstrapStaticPostgreSQLUriGrammarV4:
        expected = ContainerBootstrapStaticPostgreSQLUriGrammarV4
    elif type(grammar) is ContainerBootstrapStaticValkeyUriGrammarV4:
        expected = ContainerBootstrapStaticValkeyUriGrammarV4
    if expected is None:
        _fail("projection")
    try:
        canonical = _strict_canonical_model(grammar, expected)
        return _hash(_STATIC_URI_GRAMMAR_DOMAIN, canonical)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("projection")


class ContainerBootstrapStaticDeliveryFieldV4(_Model):
    """One exact target-usable V4 field descriptor without V1 operation binding.

    V1's descriptor binds derived fields to a full observed-operation grammar.
    V4 instead binds derived fields to the fresh static grammar hash below;
    future evidence must prove the signed V1 descriptor maps to this field.
    """

    schema_version: Literal["rsd.container-bootstrap-static-delivery-field.v4"]
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
        raise ValueError("container bootstrap V4 delivery field is invalid")

    @field_validator("sink", mode="before")
    @classmethod
    def canonical_sink(cls, value: object) -> ContainerSecretSinkV1:
        if type(value) is ContainerSecretSinkV1:
            return value
        if type(value) is str:
            try:
                return ContainerSecretSinkV1(value)
            except ValueError:
                pass
        raise ValueError("container bootstrap V4 delivery field is invalid")


class ContainerBootstrapStaticDeliveryRouteV4(_Model):
    """One exact V4 target route without output or allocation topology identity."""

    schema_version: Literal["rsd.container-bootstrap-static-delivery-route.v4"]
    component: _ComponentV4
    component_role: Literal["infisical", "valkey"]
    sink: ContainerSecretSinkV1
    fields: tuple[ContainerBootstrapStaticDeliveryFieldV4, ...] = Field(min_length=1, max_length=4)

    @field_validator("fields", mode="before")
    @classmethod
    def declared_fields(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container bootstrap V4 delivery fields")

    @field_validator("sink", mode="before")
    @classmethod
    def canonical_sink(cls, value: object) -> ContainerSecretSinkV1:
        if type(value) is ContainerSecretSinkV1:
            return value
        if type(value) is str:
            try:
                return ContainerSecretSinkV1(value)
            except ValueError:
                pass
        raise ValueError("container bootstrap V4 delivery sink is invalid")

    @model_validator(mode="after")
    def exact_route_layout(self) -> Self:
        expected: dict[
            str,
            tuple[
                ContainerSecretSinkV1,
                tuple[tuple[str, TargetDeliveryValueKindV1, str, int | None, str], ...],
            ],
        ] = {
            "primary_infisical": (
                ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                (
                    (
                        "encryption_key",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "infisical_hex_16_v1",
                        32,
                        "ENCRYPTION_KEY",
                    ),
                    (
                        "auth_secret",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "infisical_auth_secret_base64_32_v1",
                        44,
                        "AUTH_SECRET",
                    ),
                    (
                        "postgres_application_password",
                        TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
                        "derived_postgresql_uri_v1",
                        None,
                        "DB_CONNECTION_URI",
                    ),
                    (
                        "primary_valkey_password",
                        TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
                        "derived_valkey_uri_v1",
                        None,
                        "REDIS_URL",
                    ),
                ),
            ),
            "restore_infisical": (
                ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
                (
                    (
                        "encryption_key",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "infisical_hex_16_v1",
                        32,
                        "ENCRYPTION_KEY",
                    ),
                    (
                        "auth_secret",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "infisical_auth_secret_base64_32_v1",
                        44,
                        "AUTH_SECRET",
                    ),
                    (
                        "postgres_application_password",
                        TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
                        "derived_postgresql_uri_v1",
                        None,
                        "DB_CONNECTION_URI",
                    ),
                    (
                        "restore_valkey_password",
                        TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
                        "derived_valkey_uri_v1",
                        None,
                        "REDIS_URL",
                    ),
                ),
            ),
            "primary_valkey": (
                ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
                (
                    (
                        "primary_valkey_password",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "valkey_password_base64url_32_v1",
                        43,
                        "requirepass",
                    ),
                ),
            ),
            "restore_valkey": (
                ContainerSecretSinkV1.VALKEY_STDIN_CONFIGURATION,
                (
                    (
                        "restore_valkey_password",
                        TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
                        "valkey_password_base64url_32_v1",
                        43,
                        "requirepass",
                    ),
                ),
            ),
        }
        expected_sink, expected_fields = expected[self.component]
        if (
            self.component_role != _expected_role(self.component)
            or type(self.sink) is not ContainerSecretSinkV1
            or self.sink is not expected_sink
            or any(
                type(field) is not ContainerBootstrapStaticDeliveryFieldV4 for field in self.fields
            )
            or tuple(field.ordinal for field in self.fields)
            != tuple(range(1, len(self.fields) + 1))
            or len(self.fields) != len(expected_fields)
            or len({field.target_field for field in self.fields}) != len(self.fields)
            or len({field.source_purpose for field in self.fields}) != len(self.fields)
            or len({field.source_reference_sha256 for field in self.fields}) != len(self.fields)
            or len({field.source_fingerprint_sha256 for field in self.fields}) != len(self.fields)
        ):
            raise ValueError("container bootstrap V4 delivery route is invalid")
        for field, (purpose, kind, field_format, byte_count, target) in zip(
            self.fields, expected_fields, strict=True
        ):
            if (
                type(field.value_kind) is not TargetDeliveryValueKindV1
                or type(field.sink) is not ContainerSecretSinkV1
                or field.source_purpose != purpose
                or field.value_kind is not kind
                or field.format != field_format
                or (byte_count is not None and field.encoded_byte_count != byte_count)
                or field.target_field != target
                or field.sink is not self.sink
                or field.persistence_allowed is not False
                or field.logging_allowed is not False
                or field.receipt_allowed is not False
                or (
                    kind is TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL
                    and field.derivation_binding_sha256 != field.source_fingerprint_sha256
                )
            ):
                raise ValueError("container bootstrap V4 delivery route is invalid")
        return self


class ContainerBootstrapStaticDeliveryProjectionV4(_Model):
    """Four allocation-parameterized, wrapper-output-independent V4 routes.

    The projection is only a structural, value-free selection from a V1 map.
    It intentionally excludes V1 allocation topology and intent, secret
    handling, policy aggregates, map signature/hash, wrapper manifest,
    artifact, image, OCI, receipt, and effect fields.  Those are downstream
    allocation aggregate/topology, authorization, or wrapper-output facts.
    Exact URI authorities and grammar remain because target construction needs
    them before an output exists.  This projection is intentionally
    many-to-one, is not signed,
    does not verify a V1 map, and grants no delivery right.  A successor
    closure must validate the complete signed V1 map independently, bind every
    omitted field there, and prove this exact structural relation.
    """

    schema_version: Literal["rsd.container-bootstrap-static-delivery-projection.v4"]
    allocation_parameterized: Literal[True]
    generated_wrapper_output_bound: Literal[False]
    primary_postgresql_connection_uri: ContainerBootstrapStaticPostgreSQLUriGrammarV4
    restore_postgresql_connection_uri: ContainerBootstrapStaticPostgreSQLUriGrammarV4
    primary_valkey_connection_uri: ContainerBootstrapStaticValkeyUriGrammarV4
    restore_valkey_connection_uri: ContainerBootstrapStaticValkeyUriGrammarV4
    primary_infisical: ContainerBootstrapStaticDeliveryRouteV4
    primary_valkey: ContainerBootstrapStaticDeliveryRouteV4
    restore_infisical: ContainerBootstrapStaticDeliveryRouteV4
    restore_valkey: ContainerBootstrapStaticDeliveryRouteV4

    @model_validator(mode="after")
    def exact_complete_projection(self) -> Self:
        routes = (
            self.primary_infisical,
            self.primary_valkey,
            self.restore_infisical,
            self.restore_valkey,
        )
        if (
            self.allocation_parameterized is not True
            or self.generated_wrapper_output_bound is not False
            or any(type(route) is not ContainerBootstrapStaticDeliveryRouteV4 for route in routes)
            or tuple(route.component for route in routes) != _COMPONENTS
            or type(self.primary_postgresql_connection_uri)
            is not ContainerBootstrapStaticPostgreSQLUriGrammarV4
            or type(self.restore_postgresql_connection_uri)
            is not ContainerBootstrapStaticPostgreSQLUriGrammarV4
            or type(self.primary_valkey_connection_uri)
            is not ContainerBootstrapStaticValkeyUriGrammarV4
            or type(self.restore_valkey_connection_uri)
            is not ContainerBootstrapStaticValkeyUriGrammarV4
            or self.primary_postgresql_connection_uri.database_identity != "primary_database"
            or self.restore_postgresql_connection_uri.database_identity != "restore_database"
            or self.primary_postgresql_connection_uri.target_process != "primary_infisical"
            or self.restore_postgresql_connection_uri.target_process != "restore_infisical"
            or self.primary_valkey_connection_uri.cache_identity != "primary_valkey"
            or self.restore_valkey_connection_uri.cache_identity != "restore_valkey"
            or self.primary_valkey_connection_uri.target_process != "primary_infisical"
            or self.restore_valkey_connection_uri.target_process != "restore_infisical"
            or self.primary_postgresql_connection_uri.database_name
            == self.restore_postgresql_connection_uri.database_name
            or self.primary_valkey_connection_uri.authority
            == self.restore_valkey_connection_uri.authority
            or self.primary_valkey_connection_uri.password_reference_sha256
            == self.restore_valkey_connection_uri.password_reference_sha256
        ):
            raise ValueError("container bootstrap V4 delivery projection is invalid")
        self._require_derived_field(
            route=self.primary_infisical,
            target_field="DB_CONNECTION_URI",
            grammar=self.primary_postgresql_connection_uri,
        )
        self._require_derived_field(
            route=self.restore_infisical,
            target_field="DB_CONNECTION_URI",
            grammar=self.restore_postgresql_connection_uri,
        )
        self._require_derived_field(
            route=self.primary_infisical,
            target_field="REDIS_URL",
            grammar=self.primary_valkey_connection_uri,
        )
        self._require_derived_field(
            route=self.restore_infisical,
            target_field="REDIS_URL",
            grammar=self.restore_valkey_connection_uri,
        )
        return self

    @staticmethod
    def _require_derived_field(
        *,
        route: ContainerBootstrapStaticDeliveryRouteV4,
        target_field: Literal["DB_CONNECTION_URI", "REDIS_URL"],
        grammar: _StaticUriGrammarV4,
    ) -> None:
        field = next((item for item in route.fields if item.target_field == target_field), None)
        expected_kind = (
            TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI
            if target_field == "DB_CONNECTION_URI"
            else TargetDeliveryValueKindV1.DERIVED_VALKEY_URI
        )
        if type(grammar) is ContainerBootstrapStaticPostgreSQLUriGrammarV4:
            expected_reference = grammar.application_password_reference_sha256
        elif type(grammar) is ContainerBootstrapStaticValkeyUriGrammarV4:
            expected_reference = grammar.password_reference_sha256
        else:
            raise ValueError("container bootstrap V4 delivery projection is invalid")
        if (
            type(field) is not ContainerBootstrapStaticDeliveryFieldV4
            or field.value_kind is not expected_kind
            or field.encoded_byte_count != grammar.rendered_uri_byte_count
            or field.source_reference_sha256 != expected_reference
            or field.derivation_binding_sha256
            != container_bootstrap_static_uri_grammar_v4_sha256(grammar)
        ):
            raise ValueError("container bootstrap V4 delivery projection is invalid")


def _strict_canonical_projection(
    projection: ContainerBootstrapStaticDeliveryProjectionV4,
) -> ContainerBootstrapStaticDeliveryProjectionV4:
    try:
        return _strict_canonical_model(projection, ContainerBootstrapStaticDeliveryProjectionV4)
    except (TypeError, ValueError):
        pass
    _fail("projection")


def container_bootstrap_static_delivery_projection_v4_canonical_json(
    projection: ContainerBootstrapStaticDeliveryProjectionV4,
) -> bytes:
    """Render canonical V4 static-delivery projection JSON."""

    projection = _strict_canonical_projection(projection)
    try:
        return _canonical_model_bytes(projection)
    except ValueError:
        pass
    _fail("projection")


def parse_container_bootstrap_static_delivery_projection_v4_canonical_json(
    payload: bytes,
) -> ContainerBootstrapStaticDeliveryProjectionV4:
    """Parse only exact canonical V4 static-delivery projection JSON."""

    try:
        return _parse_canonical_json(payload, ContainerBootstrapStaticDeliveryProjectionV4)
    except (TypeError, ValueError):
        pass
    _fail("projection")


def container_bootstrap_static_delivery_projection_v4_sha256(
    projection: ContainerBootstrapStaticDeliveryProjectionV4,
) -> str:
    """Hash only output-independent V4 static-delivery inputs."""

    projection = _strict_canonical_projection(projection)
    try:
        return _hash(_STATIC_PROJECTION_DOMAIN, projection)
    except ValueError:
        pass
    _fail("projection")


def container_bootstrap_static_delivery_route_v4_sha256(
    route: ContainerBootstrapStaticDeliveryRouteV4,
) -> str:
    """Hash one exact V4 role route under its own domain."""

    try:
        canonical = _strict_canonical_model(route, ContainerBootstrapStaticDeliveryRouteV4)
        return _hash(_STATIC_ROUTE_DOMAIN, canonical)
    except (TypeError, ValueError):
        pass
    _fail("projection")


def container_bootstrap_static_delivery_route_v4_canonical_json(
    route: ContainerBootstrapStaticDeliveryRouteV4,
) -> bytes:
    """Render one canonical V4 route for a future target implementation."""

    try:
        canonical = _strict_canonical_model(route, ContainerBootstrapStaticDeliveryRouteV4)
        return _canonical_model_bytes(canonical)
    except (TypeError, ValueError):
        pass
    _fail("projection")


def parse_container_bootstrap_static_delivery_route_v4_canonical_json(
    payload: bytes,
) -> ContainerBootstrapStaticDeliveryRouteV4:
    """Parse only exact canonical JSON for one V4 static delivery route."""

    try:
        return _parse_canonical_json(payload, ContainerBootstrapStaticDeliveryRouteV4)
    except (TypeError, ValueError):
        pass
    _fail("projection")


def _static_postgresql_uri_grammar_from_v1(
    grammar: PostgreSQLConnectionUriGrammarV1,
) -> ContainerBootstrapStaticPostgreSQLUriGrammarV4:
    """Project only target construction facts from one V1 PostgreSQL grammar."""

    if type(grammar) is not PostgreSQLConnectionUriGrammarV1:
        raise ValueError("V1 PostgreSQL grammar is invalid")
    return ContainerBootstrapStaticPostgreSQLUriGrammarV4(
        schema_version="rsd.container-bootstrap-static-postgresql-uri-grammar.v4",
        database_identity=grammar.database_identity,
        authority=grammar.authority,
        database_name=grammar.database_name,
        application_role=grammar.application_role,
        application_password_reference_sha256=grammar.application_password_reference_sha256,
        target_process=grammar.target_process,
        environment_variable=grammar.environment_variable,
        uri_grammar=grammar.uri_grammar,
        application_password_format=grammar.application_password_format,
        application_password_encoded_byte_count=grammar.application_password_encoded_byte_count,
        rendered_uri_byte_count=grammar.rendered_uri_byte_count,
        return_uri_allowed=grammar.return_uri_allowed,
        persistent_storage_allowed=grammar.persistent_storage_allowed,
        logging_allowed=grammar.logging_allowed,
        public_artifact_allowed=grammar.public_artifact_allowed,
    )


def _static_valkey_uri_grammar_from_v1(
    grammar: ValkeyConnectionUriGrammarV1,
) -> ContainerBootstrapStaticValkeyUriGrammarV4:
    """Project only target construction facts from one V1 Valkey grammar."""

    if type(grammar) is not ValkeyConnectionUriGrammarV1:
        raise ValueError("V1 Valkey grammar is invalid")
    return ContainerBootstrapStaticValkeyUriGrammarV4(
        schema_version="rsd.container-bootstrap-static-valkey-uri-grammar.v4",
        cache_identity=grammar.cache_identity,
        authority=grammar.authority,
        database_index=grammar.database_index,
        password_reference_sha256=grammar.password_reference_sha256,
        target_process=grammar.target_process,
        environment_variable=grammar.environment_variable,
        uri_grammar=grammar.uri_grammar,
        password_format=grammar.password_format,
        password_encoded_byte_count=grammar.password_encoded_byte_count,
        rendered_uri_byte_count=grammar.rendered_uri_byte_count,
        return_uri_allowed=grammar.return_uri_allowed,
        persistent_storage_allowed=grammar.persistent_storage_allowed,
        logging_allowed=grammar.logging_allowed,
        public_artifact_allowed=grammar.public_artifact_allowed,
    )


def _static_delivery_field_from_v1(
    field: TargetDeliveryFieldV1,
    *,
    v1_grammar: PostgreSQLConnectionUriGrammarV1 | ValkeyConnectionUriGrammarV1 | None,
    static_grammar: _StaticUriGrammarV4 | None,
) -> ContainerBootstrapStaticDeliveryFieldV4:
    """Convert a validated V1 field to target-usable non-operation V4 grammar."""

    if type(field) is not TargetDeliveryFieldV1:
        raise ValueError("V1 target delivery field is invalid")
    binding = field.source_fingerprint_sha256
    if field.value_kind is TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL:
        if v1_grammar is not None or static_grammar is not None:
            raise ValueError("V1 target delivery field is invalid")
        if field.derivation_binding_sha256 != field.source_fingerprint_sha256:
            raise ValueError("V1 target delivery field is invalid")
    elif field.value_kind in {
        TargetDeliveryValueKindV1.DERIVED_POSTGRESQL_URI,
        TargetDeliveryValueKindV1.DERIVED_VALKEY_URI,
    }:
        if v1_grammar is None or static_grammar is None:
            raise ValueError("V1 target delivery field is invalid")
        if (
            field.derivation_binding_sha256 != runtime_connection_uri_grammar_sha256(v1_grammar)
            or field.encoded_byte_count != static_grammar.rendered_uri_byte_count
        ):
            raise ValueError("V1 target delivery field is invalid")
        binding = container_bootstrap_static_uri_grammar_v4_sha256(static_grammar)
    else:
        raise ValueError("V1 target delivery field is invalid")
    return ContainerBootstrapStaticDeliveryFieldV4(
        schema_version="rsd.container-bootstrap-static-delivery-field.v4",
        ordinal=field.ordinal,
        source_purpose=field.source_purpose,
        source_reference_sha256=field.source_reference_sha256,
        source_fingerprint_sha256=field.source_fingerprint_sha256,
        value_kind=field.value_kind,
        target_field=field.target_field,
        format=field.format,
        encoded_byte_count=field.encoded_byte_count,
        sink=field.sink,
        derivation_binding_sha256=binding,
        persistence_allowed=field.persistence_allowed,
        logging_allowed=field.logging_allowed,
        receipt_allowed=field.receipt_allowed,
    )


def project_target_delivery_map_v1_structurally(
    delivery_map: TargetDeliveryMapV1,
) -> ContainerBootstrapStaticDeliveryProjectionV4:
    """Select only non-output target grammar from one already-parsed V1 map.

    This helper deliberately does *not* inspect the map's allocation/policy
    aggregates, network driver/options, manifest, route artifact/image/protocol
    fields, map hash, signature, signer, or timestamp. It performs no signature
    verification and is therefore non-authorizing. A later signed-map closure
    owns those omitted bindings and must prove the exact structural relation
    again.
    """

    if type(delivery_map) is not TargetDeliveryMapV1:
        _fail("projection")
    routes: dict[str, ContainerBootstrapStaticDeliveryRouteV4] = {}
    try:
        delivery_map = TargetDeliveryMapV1.model_validate(
            delivery_map.model_dump(mode="python", warnings="error")
        )
        primary_postgresql = _static_postgresql_uri_grammar_from_v1(
            delivery_map.database_identities.primary_database.connection_uri
        )
        restore_postgresql = _static_postgresql_uri_grammar_from_v1(
            delivery_map.database_identities.restore_database.connection_uri
        )
        primary_valkey = _static_valkey_uri_grammar_from_v1(
            delivery_map.primary_valkey_connection_uri
        )
        restore_valkey = _static_valkey_uri_grammar_from_v1(
            delivery_map.restore_valkey_connection_uri
        )
        route_grammars: dict[
            str,
            tuple[
                PostgreSQLConnectionUriGrammarV1 | ValkeyConnectionUriGrammarV1 | None,
                _StaticUriGrammarV4 | None,
                PostgreSQLConnectionUriGrammarV1 | ValkeyConnectionUriGrammarV1 | None,
                _StaticUriGrammarV4 | None,
            ],
        ] = {
            "primary_infisical": (
                delivery_map.database_identities.primary_database.connection_uri,
                primary_postgresql,
                delivery_map.primary_valkey_connection_uri,
                primary_valkey,
            ),
            "restore_infisical": (
                delivery_map.database_identities.restore_database.connection_uri,
                restore_postgresql,
                delivery_map.restore_valkey_connection_uri,
                restore_valkey,
            ),
            "primary_valkey": (None, None, None, None),
            "restore_valkey": (None, None, None, None),
        }
        for component in _COMPONENTS:
            target = getattr(delivery_map, component)
            if type(target) is not ContainerTargetDeliveryV1:
                raise ValueError("V1 map route is invalid")
            postgresql_v1, postgresql_static, valkey_v1, valkey_static = route_grammars[component]
            static_fields: list[ContainerBootstrapStaticDeliveryFieldV4] = []
            for field in target.fields:
                if field.target_field == "DB_CONNECTION_URI":
                    static_fields.append(
                        _static_delivery_field_from_v1(
                            field, v1_grammar=postgresql_v1, static_grammar=postgresql_static
                        )
                    )
                elif field.target_field == "REDIS_URL":
                    static_fields.append(
                        _static_delivery_field_from_v1(
                            field, v1_grammar=valkey_v1, static_grammar=valkey_static
                        )
                    )
                else:
                    static_fields.append(
                        _static_delivery_field_from_v1(field, v1_grammar=None, static_grammar=None)
                    )
            routes[component] = ContainerBootstrapStaticDeliveryRouteV4(
                schema_version="rsd.container-bootstrap-static-delivery-route.v4",
                component=component,
                component_role=_expected_role(component),
                sink=target.sink,
                fields=tuple(static_fields),
            )
        return ContainerBootstrapStaticDeliveryProjectionV4(
            schema_version="rsd.container-bootstrap-static-delivery-projection.v4",
            allocation_parameterized=True,
            generated_wrapper_output_bound=False,
            primary_postgresql_connection_uri=primary_postgresql,
            restore_postgresql_connection_uri=restore_postgresql,
            primary_valkey_connection_uri=primary_valkey,
            restore_valkey_connection_uri=restore_valkey,
            primary_infisical=routes["primary_infisical"],
            primary_valkey=routes["primary_valkey"],
            restore_infisical=routes["restore_infisical"],
            restore_valkey=routes["restore_valkey"],
        )
    except (AttributeError, KeyError, RecursionError, TypeError, ValueError):
        pass
    _fail("projection")


def _static_argument_items(value: object, *, field: str) -> tuple[str, ...]:
    items = _items(value, field=field)
    if (
        not 1 <= len(items) <= _MAX_STATIC_ARG_ITEMS
        or any(type(item) is not str or re.fullmatch(_STATIC_ARG, item) is None for item in items)
        or sum(len(cast(str, item).encode("ascii")) for item in items)
        > _MAX_STATIC_ARG_VECTOR_BYTES
    ):
        raise ValueError("container bootstrap V4 static argv is invalid")
    return tuple(cast(str, item) for item in items)


def _canonical_static_absolute_path(value: str) -> str:
    """Return one exact V4 path spelling that can flow into Phase A.

    ``_STATIC_PATH`` already limits this to printable ASCII grammar.  The
    explicit segment checks close its otherwise ambiguous dot, duplicate- and
    trailing-slash spellings without changing any static V4 output field.
    """

    if (
        type(value) is not str
        or not value.isascii()
        or re.fullmatch(_STATIC_PATH, value) is None
        or not value.startswith("/usr/local/libexec/")
        or "\\" in value
        or "%" in value
        or "//" in value
        or value.endswith("/")
    ):
        raise ValueError("container bootstrap V4 static launch path is invalid")
    if any(part in ("", ".", "..") for part in value.split("/")[1:]):
        raise ValueError("container bootstrap V4 static launch path is invalid")
    return value


def _merged_argv_sha256(
    *,
    wrapper_argv_prefix: tuple[str, ...],
    base_entrypoint: tuple[str, ...],
    base_command: tuple[str, ...],
) -> str:
    rendered = json.dumps(
        wrapper_argv_prefix + base_entrypoint + base_command,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(_STATIC_MERGED_ARGV_DOMAIN + rendered).hexdigest()


class ContainerBootstrapStaticLaunchPlanV4(_Model):
    """Exact source input for a future wrapper's base launch, never output evidence."""

    schema_version: Literal["rsd.container-bootstrap-static-launch-plan.v4"]
    component: _ComponentV4
    component_role: Literal["infisical", "valkey"]
    base_image_policy_sha256: str = Field(pattern=_SHA256)
    base_resolution_attestation_sha256: str = Field(pattern=_SHA256)
    base_registry_index_digest_sha256: str = Field(pattern=_SHA256)
    base_linux_amd64_manifest_digest_sha256: str = Field(pattern=_SHA256)
    base_config_digest_sha256: str = Field(pattern=_SHA256)
    wrapper_executable_path: str = Field(pattern=_STATIC_PATH)
    wrapper_argv_prefix: tuple[str, ...] = Field(max_length=_MAX_STATIC_ARG_ITEMS)
    base_entrypoint: tuple[str, ...] = Field(max_length=_MAX_STATIC_ARG_ITEMS)
    base_command: tuple[str, ...] = Field(max_length=_MAX_STATIC_ARG_ITEMS)
    entrypoint_command_merge: Literal["exec_wrapper_then_base_entrypoint_and_cmd_v4"]
    merged_argv_sha256: str = Field(pattern=_SHA256)

    @field_validator("wrapper_argv_prefix", "base_entrypoint", "base_command", mode="before")
    @classmethod
    def declared_argv(cls, value: object, info: object) -> tuple[str, ...]:
        field = getattr(info, "field_name", "static argv")
        return _static_argument_items(value, field=field)

    @field_validator("wrapper_executable_path")
    @classmethod
    def canonical_wrapper_path(cls, value: str) -> str:
        return _canonical_static_absolute_path(value)

    @model_validator(mode="after")
    def exact_static_launch(self) -> Self:
        digests = (
            self.base_image_policy_sha256,
            self.base_resolution_attestation_sha256,
            self.base_registry_index_digest_sha256,
            self.base_linux_amd64_manifest_digest_sha256,
            self.base_config_digest_sha256,
            self.merged_argv_sha256,
        )
        if (
            self.component_role != _expected_role(self.component)
            or len(set(digests)) != len(digests)
            or self.wrapper_argv_prefix[0] != self.wrapper_executable_path
            or self.merged_argv_sha256
            != _merged_argv_sha256(
                wrapper_argv_prefix=self.wrapper_argv_prefix,
                base_entrypoint=self.base_entrypoint,
                base_command=self.base_command,
            )
        ):
            raise ValueError("container bootstrap V4 static launch plan is invalid")
        return self


def container_bootstrap_static_launch_plan_v4_sha256(
    plan: ContainerBootstrapStaticLaunchPlanV4,
) -> str:
    """Hash one V4 source-only launch plan."""

    try:
        canonical = _strict_canonical_model(plan, ContainerBootstrapStaticLaunchPlanV4)
        return _hash(_STATIC_LAUNCH_PLAN_DOMAIN, canonical)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_static_launch_plan_v4_canonical_json(
    plan: ContainerBootstrapStaticLaunchPlanV4,
) -> bytes:
    """Render canonical V4 source-only launch-plan JSON."""

    try:
        canonical = _strict_canonical_model(plan, ContainerBootstrapStaticLaunchPlanV4)
        return _canonical_model_bytes(canonical)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def parse_container_bootstrap_static_launch_plan_v4_canonical_json(
    payload: bytes,
) -> ContainerBootstrapStaticLaunchPlanV4:
    """Parse only exact canonical V4 source-only launch-plan JSON."""

    try:
        return _parse_canonical_json(payload, ContainerBootstrapStaticLaunchPlanV4)
    except (TypeError, ValueError):
        pass
    _fail("profile")


class ContainerBootstrapStaticPatchPreimageV4(_Model):
    """Source-only static patch input; it cannot refer to generated output."""

    schema_version: Literal["rsd.container-bootstrap-static-patch-preimage.v4"]
    wrapper_source_tree_sha256: str = Field(pattern=_SHA256)
    component: _ComponentV4
    component_role: Literal["infisical", "valkey"]
    patch_kind: Literal[
        "infisical_no_write_launcher_and_envp_v4",
        "valkey_stdin_launcher_and_acl_v4",
    ]
    patch_content_sha256: str = Field(pattern=_SHA256)
    static_launch_plan_sha256: str = Field(pattern=_SHA256)
    child_environment_policy_sha256: str = Field(pattern=_SHA256)
    static_environment_sha256: str = Field(pattern=_SHA256)
    valkey_static_configuration_sha256: str | None = Field(default=None, pattern=_SHA256)
    valkey_launch_policy_sha256: str | None = Field(default=None, pattern=_SHA256)
    infisical_ca_updater_allowed: Literal[False]
    infisical_explicit_target_envp_required: Literal[False, True]
    mutable_configuration_carrier_allowed: Literal[False]
    secret_carrier_allowed: Literal[False]
    provider_access_allowed: Literal[False]
    network_access_allowed: Literal[False]
    filesystem_output_binding_allowed: Literal[False]
    artifact_output_binding_allowed: Literal[False]
    derived_image_output_binding_allowed: Literal[False]
    provenance_sbom_repro_output_binding_allowed: Literal[False]

    @model_validator(mode="after")
    def exact_source_only_patch(self) -> Self:
        is_valkey = self.component.endswith("valkey")
        if (
            self.component_role != _expected_role(self.component)
            or (
                not is_valkey
                and (
                    self.patch_kind != "infisical_no_write_launcher_and_envp_v4"
                    or self.infisical_ca_updater_allowed is not False
                    or self.infisical_explicit_target_envp_required is not True
                    or self.valkey_static_configuration_sha256 is not None
                    or self.valkey_launch_policy_sha256 is not None
                )
            )
            or (
                is_valkey
                and (
                    self.patch_kind != "valkey_stdin_launcher_and_acl_v4"
                    or self.infisical_ca_updater_allowed is not False
                    or self.infisical_explicit_target_envp_required is not False
                    or self.valkey_static_configuration_sha256 is None
                    or self.valkey_launch_policy_sha256 is None
                )
            )
        ):
            raise ValueError("container bootstrap V4 static patch preimage is invalid")
        return self


def container_bootstrap_static_patch_preimage_v4_sha256(
    preimage: ContainerBootstrapStaticPatchPreimageV4,
) -> str:
    """Hash one V4 source-only static patch preimage."""

    try:
        canonical = _strict_canonical_model(preimage, ContainerBootstrapStaticPatchPreimageV4)
        return _hash(_STATIC_PATCH_PREIMAGE_DOMAIN, canonical)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_static_patch_preimage_v4_canonical_json(
    preimage: ContainerBootstrapStaticPatchPreimageV4,
) -> bytes:
    """Render canonical V4 source-only patch-preimage JSON."""

    try:
        canonical = _strict_canonical_model(preimage, ContainerBootstrapStaticPatchPreimageV4)
        return _canonical_model_bytes(canonical)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def parse_container_bootstrap_static_patch_preimage_v4_canonical_json(
    payload: bytes,
) -> ContainerBootstrapStaticPatchPreimageV4:
    """Parse only exact canonical V4 source-only patch-preimage JSON."""

    try:
        return _parse_canonical_json(payload, ContainerBootstrapStaticPatchPreimageV4)
    except (TypeError, ValueError):
        pass
    _fail("profile")


class ContainerBootstrapStaticPatchPolicyV4(_Model):
    """A sealed source-only patch policy that carries no build result."""

    schema_version: Literal["rsd.container-bootstrap-static-patch-policy.v4"]
    preimage: ContainerBootstrapStaticPatchPreimageV4
    static_patch_preimage_sha256: str = Field(pattern=_SHA256)
    patch_policy_intent: Literal["compile_static_target_inputs_only_v4"]
    wrapper_bytes_claimed: Literal[False]
    generated_artifact_claimed: Literal[False]
    generated_image_claimed: Literal[False]
    generated_provenance_claimed: Literal[False]
    generated_sbom_claimed: Literal[False]
    generated_reproducibility_claimed: Literal[False]

    @model_validator(mode="after")
    def exact_patch_policy(self) -> Self:
        if (
            type(self.preimage) is not ContainerBootstrapStaticPatchPreimageV4
            or self.static_patch_preimage_sha256
            != container_bootstrap_static_patch_preimage_v4_sha256(self.preimage)
        ):
            raise ValueError("container bootstrap V4 static patch policy is invalid")
        return self


def container_bootstrap_static_patch_policy_v4_sha256(
    policy: ContainerBootstrapStaticPatchPolicyV4,
) -> str:
    """Hash one V4 static patch policy without a wrapper-output dependency."""

    try:
        canonical = _strict_canonical_model(policy, ContainerBootstrapStaticPatchPolicyV4)
        return _hash(_STATIC_PATCH_POLICY_DOMAIN, canonical)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_static_patch_policy_v4_canonical_json(
    policy: ContainerBootstrapStaticPatchPolicyV4,
) -> bytes:
    """Render canonical V4 source-only patch-policy JSON."""

    try:
        canonical = _strict_canonical_model(policy, ContainerBootstrapStaticPatchPolicyV4)
        return _canonical_model_bytes(canonical)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def parse_container_bootstrap_static_patch_policy_v4_canonical_json(
    payload: bytes,
) -> ContainerBootstrapStaticPatchPolicyV4:
    """Parse only exact canonical V4 source-only patch-policy JSON."""

    try:
        return _parse_canonical_json(payload, ContainerBootstrapStaticPatchPolicyV4)
    except (TypeError, ValueError):
        pass
    _fail("profile")


class ContainerBootstrapAttachProtocolV4(_Model):
    """Fresh V4 frame grammar and limits, without a runtime codec."""

    schema_version: Literal["rsd.container-bootstrap-attach-protocol.v4"]
    protocol_name: Literal["rsd_container_bootstrap_attach_v4"]
    frame_magic: Literal["ONC4"]
    frame_version: Literal[4]
    metadata_encoding: Literal["canonical_json_utf8_v1"]
    frame_header_layout: Literal["magic_4_version_u8_type_u8_length_u32be_v1"]
    secret_chunk_ordinal_layout: Literal["u16be_v1"]
    allowed_operation_scopes: tuple[
        Literal["materialize_and_start_runtime_v1"], Literal["start_runtime_v2"]
    ]
    first_frame: Literal["ticket_envelope_v4"]
    ready_state: Literal["ready_v4"]
    claim_state: Literal["claimed_v4"]
    write_closed_state: Literal["write_closed_v4"]
    terminal_ack_state: Literal["terminal_ack_v4"]
    ambiguous_state: Literal["attach_ambiguous_v4"]
    max_metadata_bytes: int = Field(ge=512, le=16_384)
    max_chunk_bytes: int = Field(ge=1, le=65_536)
    max_chunks_per_target: int = Field(ge=1, le=4)
    max_total_secret_bytes: int = Field(ge=1, le=262_144)
    max_stdout_bytes: int = Field(ge=512, le=1_048_576)
    max_stdout_frames: int = Field(ge=1, le=1024)
    ready_timeout_seconds: int = Field(ge=1, le=60)
    claim_timeout_seconds: int = Field(ge=1, le=60)
    terminal_ack_timeout_seconds: int = Field(ge=1, le=60)
    absolute_timeout_seconds: int = Field(ge=1, le=300)
    max_ticket_lifetime_seconds: int = Field(ge=1, le=300)
    docker_non_tty_required: Literal[True]
    docker_stdout_only_required: Literal[True]
    docker_stderr_rejected: Literal[True]
    actual_write_half_close_required: Literal[True]
    eof_required_before_terminal_ack: Literal[True]
    protocol_output_eof_required_after_terminal_ack: Literal[True]
    one_attach_per_container_lifetime: Literal[True]
    replay_allowed: Literal[False]
    auto_retry_after_secret_delivery_allowed: Literal[False]
    secret_persistence_allowed: Literal[False]
    secret_logging_allowed: Literal[False]
    secret_receipt_allowed: Literal[False]

    @field_validator("allowed_operation_scopes", mode="before")
    @classmethod
    def declared_scopes(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container attach V4 operation scopes")

    @model_validator(mode="after")
    def exact_bounded_protocol(self) -> Self:
        if (
            self.allowed_operation_scopes
            != ("materialize_and_start_runtime_v1", "start_runtime_v2")
            or self.max_total_secret_bytes < self.max_chunk_bytes
            or self.max_stdout_bytes < self.max_metadata_bytes
            or self.absolute_timeout_seconds
            < max(
                self.ready_timeout_seconds,
                self.claim_timeout_seconds,
                self.terminal_ack_timeout_seconds,
            )
            or self.max_ticket_lifetime_seconds < self.absolute_timeout_seconds
        ):
            raise ValueError("container bootstrap V4 attach protocol is invalid")
        return self


def container_bootstrap_attach_v4_protocol_canonical_json(
    protocol: ContainerBootstrapAttachProtocolV4,
) -> bytes:
    """Return canonical V4 protocol JSON for future target implementations."""

    try:
        canonical = _strict_canonical_model(protocol, ContainerBootstrapAttachProtocolV4)
        return _canonical_model_bytes(canonical)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def parse_container_bootstrap_attach_v4_protocol_canonical_json(
    payload: bytes,
) -> ContainerBootstrapAttachProtocolV4:
    """Parse only exact canonical V4 protocol JSON spelling."""

    try:
        return _parse_canonical_json(payload, ContainerBootstrapAttachProtocolV4)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_attach_v4_protocol_sha256(
    protocol: ContainerBootstrapAttachProtocolV4,
) -> str:
    """Return the V4 protocol commitment used by profiles and tickets."""

    try:
        canonical = _strict_canonical_model(protocol, ContainerBootstrapAttachProtocolV4)
        return _hash(_ATTACH_PROTOCOL_DOMAIN, canonical)
    except (TypeError, ValueError):
        pass
    _fail("profile")


class ContainerAttachV4ReplayReceiptTrustAnchorV4(_Model):
    """Pinned public key for signed replay receipts in one verified profile.

    The profile envelope authenticates this distinct receipt-verification root.
    It is deliberately separate from both the external profile root and the
    profile-owned ticket signer.  No caller may provide a replacement receipt
    root at receipt-validation time.
    """

    schema_version: Literal["rsd.container-attach-replay-receipt-trust-anchor.v4"]
    key_id: str = Field(pattern=_IDENTIFIER)
    public_key_base64: str = Field(min_length=4, max_length=128)
    public_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    algorithm: Literal["ed25519"]

    @model_validator(mode="after")
    def exact_public_key(self) -> Self:
        key = _canonical_base64_bytes(self.public_key_base64)
        if len(key) != 32 or hashlib.sha256(key).hexdigest() != self.public_key_fingerprint_sha256:
            raise ValueError("container attach V4 replay receipt anchor is invalid")
        return self


class ContainerBootstrapStaticRoleProfileV4(_Model):
    """One output-independent V4 target profile for a fixed role.

    ``wrapper_source_tree_sha256`` is a caller-provided source-input
    commitment, not a Git commit or an observation of generated output.  This
    module neither discovers source control metadata nor proves a source tree
    mapping.  A future signed provenance closure must attest the source
    tree/commit relation and any artifact result independently.  The profile
    hash excludes only its own self-binding field; it excludes every artifact,
    manifest, derived image, evidence, inspection, authorization, and ticket.
    """

    schema_version: Literal["rsd.container-bootstrap-static-role-profile.v4"]
    wrapper_source_tree_sha256: str = Field(pattern=_SHA256)
    component: _ComponentV4
    component_role: Literal["infisical", "valkey"]
    compile_target: Literal["x86_64-unknown-linux-musl"]
    wrapper_executable_path: str = Field(pattern=_STATIC_PATH)
    wrapper_executable_mode: Literal["0555"]
    wrapper_executable_symlink_allowed: Literal[False]
    ticket_trust_anchor: ContainerAttachTicketTrustAnchorV1
    replay_receipt_trust_anchor: ContainerAttachV4ReplayReceiptTrustAnchorV4
    attach_protocol: ContainerBootstrapAttachProtocolV4
    static_delivery_projection: ContainerBootstrapStaticDeliveryProjectionV4
    static_delivery_projection_sha256: str = Field(pattern=_SHA256)
    selected_delivery_route: ContainerBootstrapStaticDeliveryRouteV4
    selected_delivery_route_sha256: str = Field(pattern=_SHA256)
    static_launch_plan: ContainerBootstrapStaticLaunchPlanV4
    static_launch_plan_sha256: str = Field(pattern=_SHA256)
    static_patch_preimage: ContainerBootstrapStaticPatchPreimageV4
    static_patch_preimage_sha256: str = Field(pattern=_SHA256)
    static_patch_policy: ContainerBootstrapStaticPatchPolicyV4
    static_patch_policy_sha256: str = Field(pattern=_SHA256)
    static_environment: ContainerBootstrapStaticEnvironmentV2
    child_environment_policy: ContainerBootstrapEnvironmentConstructionPolicyV2
    fd_policy: ContainerBootstrapFdPolicyV2
    pid1_policy: ContainerBootstrapPid1PolicyV2
    memory_safety_policy: ContainerBootstrapMemorySafetyPolicyV2
    valkey_launch_policy: ContainerBootstrapValkeyLaunchPolicyV2 | None = None
    profile_sha256: str = Field(pattern=_SHA256)

    @field_validator("wrapper_executable_path")
    @classmethod
    def canonical_wrapper_path(cls, value: str) -> str:
        return _canonical_static_absolute_path(value)

    @model_validator(mode="after")
    def exact_static_role_profile(self) -> Self:
        is_valkey = self.component.endswith("valkey")
        route = self.selected_delivery_route
        expected_route = getattr(self.static_delivery_projection, self.component)
        nested_exact = (
            type(self.ticket_trust_anchor) is ContainerAttachTicketTrustAnchorV1
            and type(self.replay_receipt_trust_anchor)
            is ContainerAttachV4ReplayReceiptTrustAnchorV4
            and type(self.attach_protocol) is ContainerBootstrapAttachProtocolV4
            and type(self.static_delivery_projection)
            is ContainerBootstrapStaticDeliveryProjectionV4
            and type(route) is ContainerBootstrapStaticDeliveryRouteV4
            and type(self.static_launch_plan) is ContainerBootstrapStaticLaunchPlanV4
            and type(self.static_patch_preimage) is ContainerBootstrapStaticPatchPreimageV4
            and type(self.static_patch_policy) is ContainerBootstrapStaticPatchPolicyV4
            and type(self.static_environment) is ContainerBootstrapStaticEnvironmentV2
            and type(self.child_environment_policy)
            is ContainerBootstrapEnvironmentConstructionPolicyV2
            and type(self.fd_policy) is ContainerBootstrapFdPolicyV2
            and type(self.pid1_policy) is ContainerBootstrapPid1PolicyV2
            and type(self.memory_safety_policy) is ContainerBootstrapMemorySafetyPolicyV2
            and (
                type(self.valkey_launch_policy) is ContainerBootstrapValkeyLaunchPolicyV2
                if is_valkey
                else self.valkey_launch_policy is None
            )
        )
        try:
            expected_profile_hash = _hash(_STATIC_PROFILE_DOMAIN, self, exclude={"profile_sha256"})
        except ValueError:
            expected_profile_hash = ""
        canonical_size_valid = False
        try:
            canonical_size_valid = len(_canonical_model_bytes(self)) <= _MAX_STATIC_CANONICAL_BYTES
        except (RecursionError, TypeError, ValueError):
            canonical_size_valid = False
        valid = (
            nested_exact
            and canonical_size_valid
            and self.component_role == _expected_role(self.component)
            and self.ticket_trust_anchor.key_id != self.replay_receipt_trust_anchor.key_id
            and self.ticket_trust_anchor.public_key_fingerprint_sha256
            != self.replay_receipt_trust_anchor.public_key_fingerprint_sha256
            and route == expected_route
            and route.component == self.component
            and route.component_role == self.component_role
            and self.static_delivery_projection_sha256
            == container_bootstrap_static_delivery_projection_v4_sha256(
                self.static_delivery_projection
            )
            and self.selected_delivery_route_sha256
            == container_bootstrap_static_delivery_route_v4_sha256(route)
            and self.static_launch_plan.component == self.component
            and self.static_launch_plan.component_role == self.component_role
            and self.static_launch_plan.wrapper_executable_path == self.wrapper_executable_path
            and self.static_launch_plan_sha256
            == container_bootstrap_static_launch_plan_v4_sha256(self.static_launch_plan)
            and self.static_patch_preimage.component == self.component
            and self.static_patch_preimage.component_role == self.component_role
            and self.static_patch_preimage.wrapper_source_tree_sha256
            == self.wrapper_source_tree_sha256
            and self.static_patch_preimage.static_launch_plan_sha256
            == self.static_launch_plan_sha256
            and self.static_patch_preimage.child_environment_policy_sha256
            == container_bootstrap_environment_construction_policy_sha256(
                self.child_environment_policy
            )
            and self.static_patch_preimage.static_environment_sha256
            == self.static_environment.environment_sha256
            and self.static_patch_preimage_sha256
            == container_bootstrap_static_patch_preimage_v4_sha256(self.static_patch_preimage)
            and self.static_patch_policy.preimage == self.static_patch_preimage
            and self.static_patch_policy.static_patch_preimage_sha256
            == self.static_patch_preimage_sha256
            and self.static_patch_policy_sha256
            == container_bootstrap_static_patch_policy_v4_sha256(self.static_patch_policy)
            and self.child_environment_policy.component == self.component
            and self.child_environment_policy.image_static_environment_sha256
            == self.static_environment.environment_sha256
            and self.attach_protocol.secret_persistence_allowed is False
            and self.attach_protocol.secret_logging_allowed is False
            and self.attach_protocol.secret_receipt_allowed is False
            and (
                not is_valkey
                or (
                    self.valkey_launch_policy is not None
                    and (
                        self.static_delivery_projection.primary_valkey_connection_uri.authority
                        if self.component == "primary_valkey"
                        else self.static_delivery_projection.restore_valkey_connection_uri.authority
                    )
                    == valkey_static_authority(self.valkey_launch_policy.isolated_bind_address)
                    and self.static_patch_preimage.valkey_static_configuration_sha256
                    == container_bootstrap_valkey_static_configuration_sha256(
                        self.valkey_launch_policy
                    )
                    and self.static_patch_preimage.valkey_launch_policy_sha256
                    == container_bootstrap_static_valkey_launch_policy_v4_sha256(
                        self.valkey_launch_policy
                    )
                )
            )
            and (
                is_valkey
                or (
                    self.static_patch_preimage.valkey_static_configuration_sha256 is None
                    and self.static_patch_preimage.valkey_launch_policy_sha256 is None
                )
            )
            and self.profile_sha256 == expected_profile_hash
        )
        if not valid:
            raise ValueError("container bootstrap V4 static role profile is invalid")
        return self


def build_container_bootstrap_static_role_profile_v4(
    *,
    wrapper_source_tree_sha256: str,
    component: _ComponentV4,
    component_role: Literal["infisical", "valkey"],
    compile_target: Literal["x86_64-unknown-linux-musl"],
    wrapper_executable_path: str,
    wrapper_executable_mode: Literal["0555"],
    wrapper_executable_symlink_allowed: Literal[False],
    ticket_trust_anchor: ContainerAttachTicketTrustAnchorV1,
    replay_receipt_trust_anchor: ContainerAttachV4ReplayReceiptTrustAnchorV4,
    attach_protocol: ContainerBootstrapAttachProtocolV4,
    static_delivery_projection: ContainerBootstrapStaticDeliveryProjectionV4,
    selected_delivery_route: ContainerBootstrapStaticDeliveryRouteV4,
    static_launch_plan: ContainerBootstrapStaticLaunchPlanV4,
    static_patch_preimage: ContainerBootstrapStaticPatchPreimageV4,
    static_patch_policy: ContainerBootstrapStaticPatchPolicyV4,
    static_environment: ContainerBootstrapStaticEnvironmentV2,
    child_environment_policy: ContainerBootstrapEnvironmentConstructionPolicyV2,
    fd_policy: ContainerBootstrapFdPolicyV2,
    pid1_policy: ContainerBootstrapPid1PolicyV2,
    memory_safety_policy: ContainerBootstrapMemorySafetyPolicyV2,
    valkey_launch_policy: ContainerBootstrapValkeyLaunchPolicyV2 | None,
) -> ContainerBootstrapStaticRoleProfileV4:
    """Build a self-bound V4 profile without deriving any current metadata.

    The local ``model_construct`` is used only to calculate the one permitted
    self-excluding hash. The returned model immediately undergoes normal V4
    validation, and all public verification paths reject constructed callers.
    """

    projection_sha256 = container_bootstrap_static_delivery_projection_v4_sha256(
        static_delivery_projection
    )
    route_sha256 = container_bootstrap_static_delivery_route_v4_sha256(selected_delivery_route)
    launch_sha256 = container_bootstrap_static_launch_plan_v4_sha256(static_launch_plan)
    preimage_sha256 = container_bootstrap_static_patch_preimage_v4_sha256(static_patch_preimage)
    patch_sha256 = container_bootstrap_static_patch_policy_v4_sha256(static_patch_policy)
    draft = ContainerBootstrapStaticRoleProfileV4.model_construct(
        schema_version="rsd.container-bootstrap-static-role-profile.v4",
        wrapper_source_tree_sha256=wrapper_source_tree_sha256,
        component=component,
        component_role=component_role,
        compile_target=compile_target,
        wrapper_executable_path=wrapper_executable_path,
        wrapper_executable_mode=wrapper_executable_mode,
        wrapper_executable_symlink_allowed=wrapper_executable_symlink_allowed,
        ticket_trust_anchor=ticket_trust_anchor,
        replay_receipt_trust_anchor=replay_receipt_trust_anchor,
        attach_protocol=attach_protocol,
        static_delivery_projection=static_delivery_projection,
        static_delivery_projection_sha256=projection_sha256,
        selected_delivery_route=selected_delivery_route,
        selected_delivery_route_sha256=route_sha256,
        static_launch_plan=static_launch_plan,
        static_launch_plan_sha256=launch_sha256,
        static_patch_preimage=static_patch_preimage,
        static_patch_preimage_sha256=preimage_sha256,
        static_patch_policy=static_patch_policy,
        static_patch_policy_sha256=patch_sha256,
        static_environment=static_environment,
        child_environment_policy=child_environment_policy,
        fd_policy=fd_policy,
        pid1_policy=pid1_policy,
        memory_safety_policy=memory_safety_policy,
        valkey_launch_policy=valkey_launch_policy,
        profile_sha256="0" * 64,
    )
    profile_sha256 = _hash(_STATIC_PROFILE_DOMAIN, draft, exclude={"profile_sha256"})
    try:
        return ContainerBootstrapStaticRoleProfileV4(
            schema_version="rsd.container-bootstrap-static-role-profile.v4",
            wrapper_source_tree_sha256=wrapper_source_tree_sha256,
            component=component,
            component_role=component_role,
            compile_target=compile_target,
            wrapper_executable_path=wrapper_executable_path,
            wrapper_executable_mode=wrapper_executable_mode,
            wrapper_executable_symlink_allowed=wrapper_executable_symlink_allowed,
            ticket_trust_anchor=ticket_trust_anchor,
            replay_receipt_trust_anchor=replay_receipt_trust_anchor,
            attach_protocol=attach_protocol,
            static_delivery_projection=static_delivery_projection,
            static_delivery_projection_sha256=projection_sha256,
            selected_delivery_route=selected_delivery_route,
            selected_delivery_route_sha256=route_sha256,
            static_launch_plan=static_launch_plan,
            static_launch_plan_sha256=launch_sha256,
            static_patch_preimage=static_patch_preimage,
            static_patch_preimage_sha256=preimage_sha256,
            static_patch_policy=static_patch_policy,
            static_patch_policy_sha256=patch_sha256,
            static_environment=static_environment,
            child_environment_policy=child_environment_policy,
            fd_policy=fd_policy,
            pid1_policy=pid1_policy,
            memory_safety_policy=memory_safety_policy,
            valkey_launch_policy=valkey_launch_policy,
            profile_sha256=profile_sha256,
        )
    except (TypeError, ValueError):
        pass
    _fail("profile")


def strict_canonical_container_bootstrap_static_role_profile_v4(
    profile: ContainerBootstrapStaticRoleProfileV4,
) -> ContainerBootstrapStaticRoleProfileV4:
    """Return an exact V4 static profile or a fixed public failure."""

    try:
        return _strict_canonical_model(profile, ContainerBootstrapStaticRoleProfileV4)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_static_role_profile_v4_canonical_json(
    profile: ContainerBootstrapStaticRoleProfileV4,
) -> bytes:
    """Return canonical, self-bound V4 profile JSON."""

    profile = strict_canonical_container_bootstrap_static_role_profile_v4(profile)
    try:
        return _canonical_model_bytes(profile)
    except ValueError:
        pass
    _fail("profile")


def parse_container_bootstrap_static_role_profile_v4_canonical_json(
    payload: bytes,
) -> ContainerBootstrapStaticRoleProfileV4:
    """Parse only exact canonical V4 static-profile JSON spelling."""

    try:
        return _parse_canonical_json(payload, ContainerBootstrapStaticRoleProfileV4)
    except (TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_static_role_profile_v4_sha256(
    profile: ContainerBootstrapStaticRoleProfileV4,
) -> str:
    """Return the V4 profile's single permitted self-excluding hash."""

    profile = strict_canonical_container_bootstrap_static_role_profile_v4(profile)
    try:
        expected = _hash(_STATIC_PROFILE_DOMAIN, profile, exclude={"profile_sha256"})
    except ValueError:
        expected = ""
    if profile.profile_sha256 != expected:
        _fail("profile")
    return expected


class ContainerBootstrapStaticProfileTrustAnchorV4(_Model):
    """An externally pinned public root for a compiled V4 profile envelope.

    This distinct root authenticates the supplied profile before the target
    accepts the profile-owned ticket key.  It is not an owner authorization,
    artifact proof, manifest proof, or effect permission; those closures
    remain deliberately deferred.  Ticket signature verification itself still
    uses only the key embedded in the verified static profile.
    """

    schema_version: Literal["rsd.container-bootstrap-static-profile-trust-anchor.v4"]
    key_id: str = Field(pattern=_IDENTIFIER)
    public_key_base64: str = Field(min_length=4, max_length=128)
    public_key_fingerprint_sha256: str = Field(pattern=_SHA256)
    algorithm: Literal["ed25519"]

    @model_validator(mode="after")
    def exact_public_key(self) -> Self:
        key = _canonical_base64_bytes(self.public_key_base64)
        if len(key) != 32 or hashlib.sha256(key).hexdigest() != self.public_key_fingerprint_sha256:
            raise ValueError("container bootstrap V4 profile trust anchor is invalid")
        return self


class ContainerBootstrapStaticRoleProfileEnvelopeV4(_Model):
    """A separately signed immutable identity for one static V4 profile.

    The envelope is intentionally outside the profile hash, avoiding a fixed
    point.  It authenticates only the supplied profile identity under an
    externally pinned root; it does not claim generated wrapper bytes,
    artifact provenance, OCI inspection, authorization, or runtime evidence.
    """

    schema_version: Literal["rsd.container-bootstrap-static-role-profile-envelope.v4"]
    static_role_profile: ContainerBootstrapStaticRoleProfileV4
    static_role_profile_sha256: str = Field(pattern=_SHA256)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @model_validator(mode="after")
    def exact_profile_identity(self) -> Self:
        canonical_size_valid = False
        try:
            canonical_size_valid = (
                len(_canonical_model_bytes(self)) <= _MAX_PROFILE_ENVELOPE_CANONICAL_BYTES
            )
        except (RecursionError, TypeError, ValueError):
            canonical_size_valid = False
        if (
            type(self.static_role_profile) is not ContainerBootstrapStaticRoleProfileV4
            or self.static_role_profile_sha256
            != container_bootstrap_static_role_profile_v4_sha256(self.static_role_profile)
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
            or not canonical_size_valid
        ):
            raise ValueError("container bootstrap V4 static profile envelope is invalid")
        return self


def strict_canonical_container_bootstrap_static_profile_trust_anchor_v4(
    anchor: ContainerBootstrapStaticProfileTrustAnchorV4,
) -> ContainerBootstrapStaticProfileTrustAnchorV4:
    """Return one exact external V4 profile root or a fixed public failure."""

    try:
        return _strict_canonical_model(anchor, ContainerBootstrapStaticProfileTrustAnchorV4)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_static_profile_trust_anchor_v4_canonical_json(
    anchor: ContainerBootstrapStaticProfileTrustAnchorV4,
) -> bytes:
    """Render exact canonical V4 external profile-root JSON."""

    anchor = strict_canonical_container_bootstrap_static_profile_trust_anchor_v4(anchor)
    try:
        return _canonical_model_bytes(anchor)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("profile")


def parse_container_bootstrap_static_profile_trust_anchor_v4_canonical_json(
    payload: bytes,
) -> ContainerBootstrapStaticProfileTrustAnchorV4:
    """Parse only exact bounded V4 external profile-root JSON."""

    try:
        return _parse_canonical_json(payload, ContainerBootstrapStaticProfileTrustAnchorV4)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("profile")


def strict_canonical_container_bootstrap_static_role_profile_envelope_v4(
    envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4,
) -> ContainerBootstrapStaticRoleProfileEnvelopeV4:
    """Return one exact V4 profile envelope or a fixed public failure."""

    try:
        return _strict_canonical_model(envelope, ContainerBootstrapStaticRoleProfileEnvelopeV4)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_static_role_profile_envelope_v4_canonical_json(
    envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4,
) -> bytes:
    """Render canonical V4 profile-envelope JSON without authenticating it."""

    envelope = strict_canonical_container_bootstrap_static_role_profile_envelope_v4(envelope)
    try:
        return _canonical_model_bytes(envelope)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("profile")


def parse_container_bootstrap_static_role_profile_envelope_v4_canonical_json(
    payload: bytes,
) -> ContainerBootstrapStaticRoleProfileEnvelopeV4:
    """Parse only exact bounded canonical V4 profile-envelope JSON."""

    try:
        return _parse_canonical_json(
            payload,
            ContainerBootstrapStaticRoleProfileEnvelopeV4,
            max_bytes=_MAX_PROFILE_ENVELOPE_CANONICAL_BYTES,
        )
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("profile")


def container_bootstrap_static_role_profile_envelope_v4_sha256(
    envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4,
) -> str:
    """Hash one exact signed-profile identity under a fresh V4 domain."""

    try:
        canonical = strict_canonical_container_bootstrap_static_role_profile_envelope_v4(envelope)
        return _hash(_STATIC_PROFILE_ENVELOPE_HASH_DOMAIN, canonical)
    except ContainerAttachStaticV4Error:
        pass
    _fail("profile")


def container_bootstrap_static_role_profile_envelope_v4_canonical_message(
    envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4,
) -> bytes:
    """Return the exact domain-separated Ed25519 message for profile integrity."""

    envelope = strict_canonical_container_bootstrap_static_role_profile_envelope_v4(envelope)
    try:
        return _STATIC_PROFILE_ENVELOPE_DOMAIN + _canonical_model_bytes(
            envelope, exclude={"signature_base64"}
        )
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("profile")


def verify_container_bootstrap_static_role_profile_envelope_v4(
    *,
    envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4,
    profile_trust_anchor: ContainerBootstrapStaticProfileTrustAnchorV4,
) -> ContainerBootstrapStaticRoleProfileV4:
    """Verify external profile integrity before using its embedded ticket anchor.

    This deliberately verifies *only* the profile identity.  Callers must not
    construe the returned static metadata as authorization or as a generated
    wrapper/artifact/inspection/evidence assertion.
    """

    canonical_envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4 | None = None
    canonical_anchor: ContainerBootstrapStaticProfileTrustAnchorV4 | None = None
    try:
        canonical_envelope = strict_canonical_container_bootstrap_static_role_profile_envelope_v4(
            envelope
        )
        canonical_anchor = strict_canonical_container_bootstrap_static_profile_trust_anchor_v4(
            profile_trust_anchor
        )
    except ContainerAttachStaticV4Error:
        pass
    if canonical_envelope is None or canonical_anchor is None:
        _fail("profile")
    profile = canonical_envelope.static_role_profile
    ticket_anchor = profile.ticket_trust_anchor
    receipt_anchor = profile.replay_receipt_trust_anchor
    if (
        canonical_envelope.signer_key_id != canonical_anchor.key_id
        or ticket_anchor.key_id == canonical_anchor.key_id
        or receipt_anchor.key_id == canonical_anchor.key_id
        or ticket_anchor.key_id == receipt_anchor.key_id
        or ticket_anchor.public_key_fingerprint_sha256
        == canonical_anchor.public_key_fingerprint_sha256
        or receipt_anchor.public_key_fingerprint_sha256
        == canonical_anchor.public_key_fingerprint_sha256
        or ticket_anchor.public_key_fingerprint_sha256
        == receipt_anchor.public_key_fingerprint_sha256
    ):
        _fail("profile")
    signature_valid = False
    try:
        key = Ed25519PublicKey.from_public_bytes(
            _canonical_base64_bytes(canonical_anchor.public_key_base64)
        )
        key.verify(
            _canonical_base64_bytes(canonical_envelope.signature_base64),
            container_bootstrap_static_role_profile_envelope_v4_canonical_message(
                canonical_envelope
            ),
        )
        signature_valid = True
    except (ContainerAttachStaticV4Error, InvalidSignature, ValueError):
        signature_valid = False
    if not signature_valid:
        _fail("signature")
    return profile


class ContainerAttachRuntimeBindingV4(_Model):
    """Value-free target-local facts expected before any future V4 frame."""

    schema_version: Literal["rsd.container-attach-runtime-binding.v4"]
    allocation_operation_id: str = Field(pattern=_UUID)
    operation_scope: _OperationScopeV4
    operation_id: str = Field(pattern=_UUID)
    component: _ComponentV4
    component_role: Literal["infisical", "valkey"]
    container_id: str = Field(pattern=_CONTAINER_ID)
    runtime_hostname: str = Field(pattern=_HOSTNAME)
    runtime_instance_binding_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def exact_runtime_binding(self) -> Self:
        identities = (
            self.runtime_instance_binding_sha256,
            self.request_nonce_sha256,
            self.channel_binding_sha256,
            self.session_binding_sha256,
        )
        if (
            self.component_role != _expected_role(self.component)
            or self.runtime_instance_binding_sha256
            != container_attach_v4_runtime_instance_binding_sha256(
                container_id=self.container_id,
                runtime_hostname=self.runtime_hostname,
            )
            or len(set(identities)) != len(identities)
        ):
            raise ValueError("container attach V4 runtime binding is invalid")
        return self


def container_attach_v4_runtime_binding_canonical_json(
    binding: ContainerAttachRuntimeBindingV4,
) -> bytes:
    """Render exact V4 runtime facts for a future target implementation."""

    try:
        canonical = _strict_canonical_model(binding, ContainerAttachRuntimeBindingV4)
        return _canonical_model_bytes(canonical)
    except (TypeError, ValueError):
        pass
    _fail("binding")


def parse_container_attach_v4_runtime_binding_canonical_json(
    payload: bytes,
) -> ContainerAttachRuntimeBindingV4:
    """Parse only exact canonical V4 runtime-binding JSON spelling."""

    try:
        return _parse_canonical_json(payload, ContainerAttachRuntimeBindingV4)
    except (TypeError, ValueError):
        pass
    _fail("binding")


def container_attach_v4_runtime_instance_binding_preimage(
    *, container_id: str, runtime_hostname: str
) -> bytes:
    """Return the fixed public input to the V4 runtime-binding digest."""

    if (
        type(container_id) is not str
        or re.fullmatch(_CONTAINER_ID, container_id) is None
        or type(runtime_hostname) is not str
        or re.fullmatch(_HOSTNAME, runtime_hostname) is None
    ):
        raise ValueError("container attach V4 runtime binding is invalid")
    return (
        _RUNTIME_BINDING_DOMAIN
        + container_id.encode("ascii")
        + b"\x00"
        + runtime_hostname.encode("ascii")
    )


def container_attach_v4_runtime_instance_binding_sha256(
    *, container_id: str, runtime_hostname: str
) -> str:
    """Bind full target container identity and runtime hostname under V4."""

    return hashlib.sha256(
        container_attach_v4_runtime_instance_binding_preimage(
            container_id=container_id,
            runtime_hostname=runtime_hostname,
        )
    ).hexdigest()


class ContainerAttachRequestV4(_Model):
    """Value-free V4 ticket request preceding a deliberately deferred frame stream."""

    schema_version: Literal["rsd.container-attach-request.v4"]
    allocation_operation_id: str = Field(pattern=_UUID)
    operation_scope: _OperationScopeV4
    operation_id: str = Field(pattern=_UUID)
    component: _ComponentV4
    component_role: Literal["infisical", "valkey"]
    container_id: str = Field(pattern=_CONTAINER_ID)
    runtime_hostname: str = Field(pattern=_HOSTNAME)
    runtime_instance_binding_sha256: str = Field(pattern=_SHA256)
    static_role_profile_sha256: str = Field(pattern=_SHA256)
    static_role_profile_envelope_sha256: str = Field(pattern=_SHA256)
    static_profile_trust_anchor_fingerprint_sha256: str = Field(pattern=_SHA256)
    replay_receipt_trust_anchor_key_id: str = Field(pattern=_IDENTIFIER)
    replay_receipt_trust_anchor_fingerprint_sha256: str = Field(pattern=_SHA256)
    static_delivery_projection_sha256: str = Field(pattern=_SHA256)
    selected_delivery_route_sha256: str = Field(pattern=_SHA256)
    attach_protocol_v4_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    expected_ready_state: Literal["ready_v4"]
    expected_claim_state: Literal["claimed_v4"]
    expected_terminal_ack_state: Literal["terminal_ack_v4"]
    fields: tuple[ContainerBootstrapStaticDeliveryFieldV4, ...] = Field(min_length=1, max_length=4)

    @field_validator("fields", mode="before")
    @classmethod
    def declared_fields(cls, value: object) -> tuple[object, ...]:
        return _items(value, field="container attach V4 request fields")

    @model_validator(mode="after")
    def exact_value_free_request(self) -> Self:
        identities = (
            self.runtime_instance_binding_sha256,
            self.static_role_profile_sha256,
            self.static_role_profile_envelope_sha256,
            self.static_profile_trust_anchor_fingerprint_sha256,
            self.replay_receipt_trust_anchor_fingerprint_sha256,
            self.static_delivery_projection_sha256,
            self.selected_delivery_route_sha256,
            self.attach_protocol_v4_sha256,
            self.request_nonce_sha256,
            self.channel_binding_sha256,
            self.session_binding_sha256,
        )
        if (
            self.component_role != _expected_role(self.component)
            or self.runtime_instance_binding_sha256
            != container_attach_v4_runtime_instance_binding_sha256(
                container_id=self.container_id,
                runtime_hostname=self.runtime_hostname,
            )
            or any(
                type(field) is not ContainerBootstrapStaticDeliveryFieldV4 for field in self.fields
            )
            or tuple(field.ordinal for field in self.fields)
            != tuple(range(1, len(self.fields) + 1))
            or len(set(identities)) != len(identities)
        ):
            raise ValueError("container attach V4 request is invalid")
        return self


def strict_canonical_container_attach_request_v4(
    request: ContainerAttachRequestV4,
) -> ContainerAttachRequestV4:
    """Return an exact V4 request or a fixed public ticket failure."""

    try:
        return _strict_canonical_model(request, ContainerAttachRequestV4)
    except (TypeError, ValueError):
        pass
    _fail("ticket")


def container_attach_v4_request_canonical_json(request: ContainerAttachRequestV4) -> bytes:
    """Render canonical V4 request JSON for cross-language consumers."""

    request = strict_canonical_container_attach_request_v4(request)
    try:
        return _canonical_model_bytes(request)
    except ValueError:
        pass
    _fail("ticket")


def parse_container_attach_v4_request_canonical_json(payload: bytes) -> ContainerAttachRequestV4:
    """Parse only exact canonical V4 request JSON spelling."""

    try:
        return _parse_canonical_json(
            payload, ContainerAttachRequestV4, max_bytes=_MAX_ATTACH_METADATA_BYTES
        )
    except (TypeError, ValueError):
        pass
    _fail("ticket")


def container_attach_v4_request_sha256(request: ContainerAttachRequestV4) -> str:
    """Return the V4 request commitment signed by an authorization ticket."""

    request = strict_canonical_container_attach_request_v4(request)
    try:
        return _hash(_ATTACH_REQUEST_DOMAIN, request)
    except ValueError:
        pass
    _fail("ticket")


class ContainerAttachAuthorizationTicketV4(_Model):
    """Signed V4 dynamic ticket, verified only with the profile-owned key."""

    schema_version: Literal["rsd.container-attach-authorization-ticket.v4"]
    protocol_sha256: str = Field(pattern=_SHA256)
    request_sha256: str = Field(pattern=_SHA256)
    allocation_operation_id: str = Field(pattern=_UUID)
    operation_scope: _OperationScopeV4
    operation_id: str = Field(pattern=_UUID)
    component: _ComponentV4
    component_role: Literal["infisical", "valkey"]
    container_id: str = Field(pattern=_CONTAINER_ID)
    runtime_hostname: str = Field(pattern=_HOSTNAME)
    runtime_instance_binding_sha256: str = Field(pattern=_SHA256)
    static_role_profile_sha256: str = Field(pattern=_SHA256)
    static_role_profile_envelope_sha256: str = Field(pattern=_SHA256)
    static_profile_trust_anchor_fingerprint_sha256: str = Field(pattern=_SHA256)
    replay_receipt_trust_anchor_key_id: str = Field(pattern=_IDENTIFIER)
    replay_receipt_trust_anchor_fingerprint_sha256: str = Field(pattern=_SHA256)
    static_delivery_projection_sha256: str = Field(pattern=_SHA256)
    selected_delivery_route_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    issued_at: str
    expires_at: str
    signer_key_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _canonical_timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_dynamic_ticket(self) -> Self:
        identities = (
            self.protocol_sha256,
            self.request_sha256,
            self.runtime_instance_binding_sha256,
            self.static_role_profile_sha256,
            self.static_role_profile_envelope_sha256,
            self.static_profile_trust_anchor_fingerprint_sha256,
            self.replay_receipt_trust_anchor_fingerprint_sha256,
            self.static_delivery_projection_sha256,
            self.selected_delivery_route_sha256,
            self.request_nonce_sha256,
            self.channel_binding_sha256,
            self.session_binding_sha256,
        )
        lifetime = _canonical_timestamp(self.expires_at) - _canonical_timestamp(self.issued_at)
        signature = _canonical_base64_bytes(self.signature_base64)
        if (
            self.component_role != _expected_role(self.component)
            or self.runtime_instance_binding_sha256
            != container_attach_v4_runtime_instance_binding_sha256(
                container_id=self.container_id,
                runtime_hostname=self.runtime_hostname,
            )
            or len(set(identities)) != len(identities)
            or lifetime <= timedelta(0)
            or lifetime > timedelta(seconds=300)
            or len(signature) != 64
        ):
            raise ValueError("container attach V4 ticket is invalid")
        return self


def strict_canonical_container_attach_authorization_ticket_v4(
    ticket: ContainerAttachAuthorizationTicketV4,
) -> ContainerAttachAuthorizationTicketV4:
    """Return an exact V4 signed ticket or a fixed public error."""

    try:
        return _strict_canonical_model(ticket, ContainerAttachAuthorizationTicketV4)
    except (TypeError, ValueError):
        pass
    _fail("ticket")


def container_attach_v4_ticket_canonical_message(
    ticket: ContainerAttachAuthorizationTicketV4,
) -> bytes:
    """Return exact Ed25519 V4 ticket bytes without the signature field."""

    ticket = strict_canonical_container_attach_authorization_ticket_v4(ticket)
    try:
        return _ATTACH_TICKET_DOMAIN + _canonical_model_bytes(ticket, exclude={"signature_base64"})
    except ValueError:
        pass
    _fail("ticket")


def container_attach_v4_ticket_canonical_json(
    ticket: ContainerAttachAuthorizationTicketV4,
) -> bytes:
    """Render canonical V4 signed-ticket JSON for cross-language validation."""

    ticket = strict_canonical_container_attach_authorization_ticket_v4(ticket)
    try:
        return _canonical_model_bytes(ticket)
    except ValueError:
        pass
    _fail("ticket")


def parse_container_attach_v4_ticket_canonical_json(
    payload: bytes,
) -> ContainerAttachAuthorizationTicketV4:
    """Parse only exact canonical V4 signed-ticket JSON spelling."""

    try:
        return _parse_canonical_json(
            payload, ContainerAttachAuthorizationTicketV4, max_bytes=_MAX_ATTACH_METADATA_BYTES
        )
    except (TypeError, ValueError):
        pass
    _fail("ticket")


def container_attach_v4_ticket_sha256(ticket: ContainerAttachAuthorizationTicketV4) -> str:
    """Return a receipt-safe V4 commitment to one signed ticket."""

    ticket = strict_canonical_container_attach_authorization_ticket_v4(ticket)
    try:
        return _hash(_ATTACH_TICKET_HASH_DOMAIN, ticket)
    except ValueError:
        pass
    _fail("ticket")


class ContainerAttachTicketEnvelopeV4(_Model):
    """The future first V4 metadata frame, but not a raw frame codec."""

    schema_version: Literal["rsd.container-attach-ticket-envelope.v4"]
    request: ContainerAttachRequestV4
    ticket: ContainerAttachAuthorizationTicketV4

    @model_validator(mode="after")
    def exact_request_ticket_binding(self) -> Self:
        request = self.request
        ticket = self.ticket
        exact = (
            type(request) is ContainerAttachRequestV4
            and type(ticket) is ContainerAttachAuthorizationTicketV4
            and ticket.request_sha256 == container_attach_v4_request_sha256(request)
            and ticket.protocol_sha256 == request.attach_protocol_v4_sha256
            and ticket.allocation_operation_id == request.allocation_operation_id
            and ticket.operation_scope == request.operation_scope
            and ticket.operation_id == request.operation_id
            and ticket.component == request.component
            and ticket.component_role == request.component_role
            and ticket.container_id == request.container_id
            and ticket.runtime_hostname == request.runtime_hostname
            and ticket.runtime_instance_binding_sha256 == request.runtime_instance_binding_sha256
            and ticket.static_role_profile_sha256 == request.static_role_profile_sha256
            and ticket.static_role_profile_envelope_sha256
            == request.static_role_profile_envelope_sha256
            and ticket.static_profile_trust_anchor_fingerprint_sha256
            == request.static_profile_trust_anchor_fingerprint_sha256
            and ticket.replay_receipt_trust_anchor_key_id
            == request.replay_receipt_trust_anchor_key_id
            and ticket.replay_receipt_trust_anchor_fingerprint_sha256
            == request.replay_receipt_trust_anchor_fingerprint_sha256
            and ticket.static_delivery_projection_sha256
            == request.static_delivery_projection_sha256
            and ticket.selected_delivery_route_sha256 == request.selected_delivery_route_sha256
            and ticket.request_nonce_sha256 == request.request_nonce_sha256
            and ticket.channel_binding_sha256 == request.channel_binding_sha256
            and ticket.session_binding_sha256 == request.session_binding_sha256
        )
        if not exact:
            raise ValueError("container attach V4 ticket envelope is invalid")
        return self


def strict_canonical_container_attach_ticket_envelope_v4(
    envelope: ContainerAttachTicketEnvelopeV4,
) -> ContainerAttachTicketEnvelopeV4:
    """Return an exact V4 envelope or a fixed public error."""

    try:
        return _strict_canonical_model(envelope, ContainerAttachTicketEnvelopeV4)
    except (TypeError, ValueError):
        pass
    _fail("ticket")


def container_attach_v4_ticket_envelope_canonical_json(
    envelope: ContainerAttachTicketEnvelopeV4,
) -> bytes:
    """Render canonical V4 envelope metadata; a raw frame codec is deferred."""

    envelope = strict_canonical_container_attach_ticket_envelope_v4(envelope)
    try:
        return _canonical_model_bytes(envelope)
    except ValueError:
        pass
    _fail("ticket")


def parse_container_attach_v4_ticket_envelope_canonical_json(
    payload: bytes,
) -> ContainerAttachTicketEnvelopeV4:
    """Parse generic bounded V4 envelope JSON without making it usable.

    This standalone parser intentionally has only the module-wide metadata
    ceiling. A target that has a verified static profile must use
    :func:`parse_container_attach_v4_ticket_envelope_for_profile_v4`, which
    applies that profile's signed exact metadata limit before parsing.
    """

    try:
        return _parse_canonical_json(
            payload, ContainerAttachTicketEnvelopeV4, max_bytes=_MAX_ATTACH_METADATA_BYTES
        )
    except (TypeError, ValueError):
        pass
    _fail("ticket")


def parse_container_attach_v4_ticket_envelope_for_profile_v4(
    *,
    static_role_profile_envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4,
    profile_trust_anchor: ContainerBootstrapStaticProfileTrustAnchorV4,
    payload: bytes,
) -> ContainerAttachTicketEnvelopeV4:
    """Parse a raw envelope only under its verified profile's signed limit.

    This remains a parsing/validation primitive, not authorization or a frame
    consumer. It verifies the separate profile-integrity envelope first, then
    rejects a raw metadata payload exceeding the exact signed protocol cap
    before JSON parsing or delivery-frame handling.
    """

    profile = verify_container_bootstrap_static_role_profile_envelope_v4(
        envelope=static_role_profile_envelope,
        profile_trust_anchor=profile_trust_anchor,
    )
    try:
        return _parse_canonical_json(
            payload,
            ContainerAttachTicketEnvelopeV4,
            max_bytes=profile.attach_protocol.max_metadata_bytes,
        )
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("ticket")


class ContainerAttachV4TicketValidation(_Model):
    """A value-free validation result; it is never a bearer authorization."""

    schema_version: Literal["rsd.container-attach-ticket-validation.v4"]
    component: _ComponentV4
    component_role: Literal["infisical", "valkey"]
    static_role_profile_sha256: str = Field(pattern=_SHA256)
    static_role_profile_envelope_sha256: str = Field(pattern=_SHA256)
    static_profile_trust_anchor_fingerprint_sha256: str = Field(pattern=_SHA256)
    replay_receipt_trust_anchor_key_id: str = Field(pattern=_IDENTIFIER)
    replay_receipt_trust_anchor_fingerprint_sha256: str = Field(pattern=_SHA256)
    static_delivery_projection_sha256: str = Field(pattern=_SHA256)
    selected_delivery_route_sha256: str = Field(pattern=_SHA256)
    attach_protocol_v4_sha256: str = Field(pattern=_SHA256)
    request_sha256: str = Field(pattern=_SHA256)
    ticket_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)
    allocation_operation_id: str = Field(pattern=_UUID)
    operation_scope: _OperationScopeV4
    operation_id: str = Field(pattern=_UUID)
    container_id: str = Field(pattern=_CONTAINER_ID)
    runtime_hostname: str = Field(pattern=_HOSTNAME)
    runtime_instance_binding_sha256: str = Field(pattern=_SHA256)
    freshness_checked_at: str
    issued_at: str
    expires_at: str
    claim_timeout_seconds: int = Field(ge=1, le=60)
    max_ticket_lifetime_seconds: int = Field(ge=1, le=300)


class ContainerAttachV4TicketReplayClaimV4(_Model):
    """The exact nonsecret identity of one V4 signed ticket instance."""

    schema_version: Literal["rsd.container-attach-ticket-replay-claim.v4"]
    static_role_profile_sha256: str = Field(pattern=_SHA256)
    static_role_profile_envelope_sha256: str = Field(pattern=_SHA256)
    static_profile_trust_anchor_fingerprint_sha256: str = Field(pattern=_SHA256)
    request_sha256: str = Field(pattern=_SHA256)
    ticket_sha256: str = Field(pattern=_SHA256)
    allocation_operation_id: str = Field(pattern=_UUID)
    operation_scope: _OperationScopeV4
    operation_id: str = Field(pattern=_UUID)
    component: _ComponentV4
    component_role: Literal["infisical", "valkey"]
    container_id: str = Field(pattern=_CONTAINER_ID)
    runtime_hostname: str = Field(pattern=_HOSTNAME)
    runtime_instance_binding_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    session_binding_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def exact_ticket_claim_identity(self) -> Self:
        identities = (
            self.static_role_profile_sha256,
            self.static_role_profile_envelope_sha256,
            self.static_profile_trust_anchor_fingerprint_sha256,
            self.request_sha256,
            self.ticket_sha256,
            self.request_nonce_sha256,
            self.channel_binding_sha256,
            self.session_binding_sha256,
        )
        if (
            self.component not in _COMPONENTS
            or self.component_role != _expected_role(self.component)
            or len(set(identities)) != len(identities)
            or self.runtime_instance_binding_sha256
            != container_attach_v4_runtime_instance_binding_sha256(
                container_id=self.container_id,
                runtime_hostname=self.runtime_hostname,
            )
        ):
            raise ValueError("container attach V4 ticket replay claim is invalid")
        return self


class ContainerAttachV4ContainerLifetimeClaimV4(_Model):
    """Stable one-attach identity: the immutable container ID alone.

    This deliberately excludes profile, role, hostname, ticket, signature,
    timestamps, nonce, channel, and session. Reissued tickets or profiles
    cannot make the same immutable target container attachable a second time.
    """

    schema_version: Literal["rsd.container-attach-container-lifetime-claim.v4"]
    container_id: str = Field(pattern=_CONTAINER_ID)
    one_attach_per_container_lifetime: Literal[True]


class ContainerAttachV4ReplayClaimV4(_Model):
    """One atomic V4 request containing ticket and container-lifetime keys."""

    schema_version: Literal["rsd.container-attach-replay-claim.v4"]
    ticket_claim: ContainerAttachV4TicketReplayClaimV4
    container_lifetime_claim: ContainerAttachV4ContainerLifetimeClaimV4

    @model_validator(mode="after")
    def exact_atomic_claim_binding(self) -> Self:
        if (
            type(self.ticket_claim) is not ContainerAttachV4TicketReplayClaimV4
            or type(self.container_lifetime_claim) is not ContainerAttachV4ContainerLifetimeClaimV4
            or self.ticket_claim.container_id != self.container_lifetime_claim.container_id
        ):
            raise ValueError("container attach V4 replay claim is invalid")
        return self


def _ticket_replay_claim_matches_validation(
    claim: ContainerAttachV4TicketReplayClaimV4,
    validation: ContainerAttachV4TicketValidation,
) -> bool:
    """Require every authority-consumed ticket key to equal validated input.

    The external authority sees a preparation before finalization.  Leaving
    any dynamic identity unchecked here would let a forged self-hashed
    preparation consume the stable container-lifetime key and only fail after
    that irreversible claim.  Keep this equality deliberately exhaustive.
    """

    return (
        claim.static_role_profile_sha256 == validation.static_role_profile_sha256
        and claim.static_role_profile_envelope_sha256
        == validation.static_role_profile_envelope_sha256
        and claim.static_profile_trust_anchor_fingerprint_sha256
        == validation.static_profile_trust_anchor_fingerprint_sha256
        and claim.request_sha256 == validation.request_sha256
        and claim.ticket_sha256 == validation.ticket_sha256
        and claim.allocation_operation_id == validation.allocation_operation_id
        and claim.operation_scope == validation.operation_scope
        and claim.operation_id == validation.operation_id
        and claim.component == validation.component
        and claim.component_role == validation.component_role
        and claim.container_id == validation.container_id
        and claim.runtime_hostname == validation.runtime_hostname
        and claim.runtime_instance_binding_sha256 == validation.runtime_instance_binding_sha256
        and claim.request_nonce_sha256 == validation.request_nonce_sha256
        and claim.channel_binding_sha256 == validation.channel_binding_sha256
        and claim.session_binding_sha256 == validation.session_binding_sha256
    )


class ContainerAttachV4ClaimDeadlineV4(_Model):
    """Frozen value-only deadline policy for one external atomic claim.

    The effective UTC cutoff is the signed ticket's exclusive expiry.  The
    timeout is a separately profile-bound budget which an authority must apply
    with *its own* local monotonic interval while making both replay keys
    unique.  This record deliberately contains no callback, clock, guard,
    interval, registry, or cross-process monotonic value.
    """

    schema_version: Literal["rsd.container-attach-claim-deadline.v4"]
    ticket_sha256: str
    ticket_expires_at: str
    effective_deadline_at: str
    claim_timeout_seconds: int
    atomic_deadline_predicate_required: Literal[True]
    authority_local_monotonic_budget_required: Literal[True]

    @model_validator(mode="after")
    def exact_value_only_deadline(self) -> Self:
        if (
            self.schema_version != "rsd.container-attach-claim-deadline.v4"
            or type(self.ticket_sha256) is not str
            or re.fullmatch(_SHA256, self.ticket_sha256) is None
            or type(self.claim_timeout_seconds) is not int
            or not 1 <= self.claim_timeout_seconds <= 60
            or self.atomic_deadline_predicate_required is not True
            or self.authority_local_monotonic_budget_required is not True
        ):
            raise ValueError("container attach V4 claim deadline is invalid")
        expires = _canonical_timestamp(self.ticket_expires_at)
        deadline = _canonical_timestamp(self.effective_deadline_at)
        if deadline != expires:
            raise ValueError("container attach V4 claim deadline is invalid")
        return self


def strict_canonical_container_attach_v4_ticket_replay_claim(
    claim: ContainerAttachV4TicketReplayClaimV4,
) -> ContainerAttachV4TicketReplayClaimV4:
    """Return one exact V4 ticket-instance claim or a fixed replay failure."""

    try:
        return _strict_canonical_model(claim, ContainerAttachV4TicketReplayClaimV4)
    except (TypeError, ValueError):
        pass
    _fail("replay")


def container_attach_v4_ticket_replay_claim_sha256(
    claim: ContainerAttachV4TicketReplayClaimV4,
) -> str:
    """Hash one V4 ticket-instance replay claim."""

    try:
        return _hash(
            _TICKET_REPLAY_CLAIM_DOMAIN,
            strict_canonical_container_attach_v4_ticket_replay_claim(claim),
        )
    except ContainerAttachStaticV4Error:
        pass
    _fail("replay")


def strict_canonical_container_attach_v4_container_lifetime_claim(
    claim: ContainerAttachV4ContainerLifetimeClaimV4,
) -> ContainerAttachV4ContainerLifetimeClaimV4:
    """Return one exact V4 container-lifetime claim or a fixed failure."""

    try:
        return _strict_canonical_model(claim, ContainerAttachV4ContainerLifetimeClaimV4)
    except (TypeError, ValueError):
        pass
    _fail("replay")


def container_attach_v4_container_lifetime_claim_sha256(
    claim: ContainerAttachV4ContainerLifetimeClaimV4,
) -> str:
    """Hash one stable container-ID-only V4 lifetime identity."""

    try:
        return _hash(
            _CONTAINER_LIFETIME_CLAIM_DOMAIN,
            strict_canonical_container_attach_v4_container_lifetime_claim(claim),
        )
    except ContainerAttachStaticV4Error:
        pass
    _fail("replay")


def strict_canonical_container_attach_v4_replay_claim(
    claim: ContainerAttachV4ReplayClaimV4,
) -> ContainerAttachV4ReplayClaimV4:
    """Return one exact atomic V4 replay request or a fixed failure."""

    try:
        return _strict_canonical_model(claim, ContainerAttachV4ReplayClaimV4)
    except (TypeError, ValueError):
        pass
    _fail("replay")


def container_attach_v4_replay_claim_canonical_json(claim: ContainerAttachV4ReplayClaimV4) -> bytes:
    """Render both atomic V4 replay identities for future target consumers."""

    claim = strict_canonical_container_attach_v4_replay_claim(claim)
    try:
        return _canonical_model_bytes(claim)
    except ValueError:
        pass
    _fail("replay")


def parse_container_attach_v4_replay_claim_canonical_json(
    payload: bytes,
) -> ContainerAttachV4ReplayClaimV4:
    """Parse only exact canonical V4 replay-key JSON spelling."""

    try:
        return _parse_canonical_json(payload, ContainerAttachV4ReplayClaimV4)
    except (TypeError, ValueError):
        pass
    _fail("replay")


def container_attach_v4_replay_claim_sha256(claim: ContainerAttachV4ReplayClaimV4) -> str:
    """Hash one complete exact-once V4 replay key."""

    try:
        return _hash(_REPLAY_CLAIM_DOMAIN, strict_canonical_container_attach_v4_replay_claim(claim))
    except ContainerAttachStaticV4Error:
        pass
    _fail("replay")


def container_attach_v4_replay_receipt_trust_anchor_v4_canonical_json(
    anchor: ContainerAttachV4ReplayReceiptTrustAnchorV4,
) -> bytes:
    """Render exact canonical V4 external replay-receipt-root JSON."""

    try:
        canonical = _strict_canonical_model(anchor, ContainerAttachV4ReplayReceiptTrustAnchorV4)
        return _canonical_model_bytes(canonical)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


def parse_container_attach_v4_replay_receipt_trust_anchor_v4_canonical_json(
    payload: bytes,
) -> ContainerAttachV4ReplayReceiptTrustAnchorV4:
    """Parse only exact bounded V4 external replay-receipt-root JSON."""

    try:
        return _parse_canonical_json(
            payload,
            ContainerAttachV4ReplayReceiptTrustAnchorV4,
            max_bytes=_MAX_ATTACH_METADATA_BYTES,
        )
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


class ContainerAttachV4ClaimPreparationV4(_Model):
    """Non-authorizing checked input for an external atomic replay operation.

    A caller first prepares this record after all canonical/profile/ticket and
    freshness checks.  A separately trusted future executor closure must
    atomically claim both keys and sign a receipt after it authenticates its
    peer.  Receipt validation then rechecks raw inputs, freshness, the
    immutable deadline, and that receipt.  Preparation itself is never a
    delivery capability and cannot cause a frame/effect.
    """

    schema_version: Literal["rsd.container-attach-claim-preparation.v4"]
    validation: ContainerAttachV4TicketValidation
    replay_claim: ContainerAttachV4ReplayClaimV4
    replay_claim_sha256: str = Field(pattern=_SHA256)
    ticket_replay_claim_sha256: str = Field(pattern=_SHA256)
    container_lifetime_claim_sha256: str = Field(pattern=_SHA256)
    claim_deadline: ContainerAttachV4ClaimDeadlineV4
    preparation_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def exact_non_authorizing_preparation(self) -> Self:
        validation = self.validation
        claim = self.replay_claim
        if (
            type(validation) is not ContainerAttachV4TicketValidation
            or type(claim) is not ContainerAttachV4ReplayClaimV4
            or type(self.claim_deadline) is not ContainerAttachV4ClaimDeadlineV4
            or self.replay_claim_sha256 != container_attach_v4_replay_claim_sha256(claim)
            or self.ticket_replay_claim_sha256
            != container_attach_v4_ticket_replay_claim_sha256(claim.ticket_claim)
            or self.container_lifetime_claim_sha256
            != container_attach_v4_container_lifetime_claim_sha256(claim.container_lifetime_claim)
            or self.claim_deadline.ticket_sha256 != validation.ticket_sha256
            or self.claim_deadline.ticket_expires_at != validation.expires_at
            or self.claim_deadline.effective_deadline_at != validation.expires_at
            or self.claim_deadline.claim_timeout_seconds != validation.claim_timeout_seconds
            or claim != _replay_claim_from_validation(validation)
        ):
            raise ValueError("container attach V4 claim preparation is invalid")
        expected = _hash(_REPLAY_PREPARATION_DOMAIN, self, exclude={"preparation_sha256"})
        if self.preparation_sha256 != expected:
            raise ValueError("container attach V4 claim preparation is invalid")
        return self


def build_container_attach_v4_claim_preparation(
    *,
    validation: ContainerAttachV4TicketValidation,
    claim_deadline: ContainerAttachV4ClaimDeadlineV4,
) -> ContainerAttachV4ClaimPreparationV4:
    """Build one derived, non-authorizing external-claim preparation.

    The replay identities are derived solely from the already validated signed
    graph.  This public builder intentionally has no caller-provided claim
    parameter, so a caller cannot spend a durable authority key for another
    operation or container.
    """

    try:
        validation = _strict_canonical_model(validation, ContainerAttachV4TicketValidation)
    except (RecursionError, TypeError, ValueError):
        _fail("replay")
    replay_claim = _replay_claim_from_validation(validation)

    replay_claim_sha256 = container_attach_v4_replay_claim_sha256(replay_claim)
    ticket_replay_claim_sha256 = container_attach_v4_ticket_replay_claim_sha256(
        replay_claim.ticket_claim
    )
    lifetime_claim_sha256 = container_attach_v4_container_lifetime_claim_sha256(
        replay_claim.container_lifetime_claim
    )
    draft = ContainerAttachV4ClaimPreparationV4.model_construct(
        schema_version="rsd.container-attach-claim-preparation.v4",
        validation=validation,
        replay_claim=replay_claim,
        replay_claim_sha256=replay_claim_sha256,
        ticket_replay_claim_sha256=ticket_replay_claim_sha256,
        container_lifetime_claim_sha256=lifetime_claim_sha256,
        claim_deadline=claim_deadline,
        preparation_sha256="0" * 64,
    )
    preparation_sha256 = _hash(_REPLAY_PREPARATION_DOMAIN, draft, exclude={"preparation_sha256"})
    try:
        return ContainerAttachV4ClaimPreparationV4(
            schema_version="rsd.container-attach-claim-preparation.v4",
            validation=validation,
            replay_claim=replay_claim,
            replay_claim_sha256=replay_claim_sha256,
            ticket_replay_claim_sha256=ticket_replay_claim_sha256,
            container_lifetime_claim_sha256=lifetime_claim_sha256,
            claim_deadline=claim_deadline,
            preparation_sha256=preparation_sha256,
        )
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


def container_attach_v4_claim_preparation_canonical_json(
    preparation: ContainerAttachV4ClaimPreparationV4,
) -> bytes:
    """Render exact non-authorizing V4 external-claim preparation JSON."""

    try:
        canonical = _strict_canonical_model(preparation, ContainerAttachV4ClaimPreparationV4)
        return _canonical_model_bytes(canonical)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


def parse_container_attach_v4_claim_preparation_canonical_json(
    payload: bytes,
) -> ContainerAttachV4ClaimPreparationV4:
    """Parse only exact bounded V4 external-claim preparation JSON."""

    try:
        return _parse_canonical_json(
            payload, ContainerAttachV4ClaimPreparationV4, max_bytes=_MAX_ATTACH_METADATA_BYTES
        )
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


class ContainerAttachV4ClaimIntentV4(_Model):
    """A non-authorizing V4 statement of future peer-authenticated intent.

    This complete signed graph is deliberately *not* a bearer request to an
    atomic replay authority.  V4 has no authenticated executor transport or
    proof-of-possession channel, so serializing this object cannot invoke
    durable replay persistence.  A later closure must bind this intent to an
    independently observed peer-authenticated executor capability and perform
    atomic persistence in that channel.
    """

    schema_version: Literal["rsd.container-attach-claim-intent.v4"]
    static_role_profile_envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4
    ticket_envelope: ContainerAttachTicketEnvelopeV4
    expected_runtime: ContainerAttachRuntimeBindingV4
    preparation: ContainerAttachV4ClaimPreparationV4
    replay_receipt_trust_anchor_key_id: str = Field(pattern=_IDENTIFIER)
    replay_receipt_trust_anchor_fingerprint_sha256: str = Field(pattern=_SHA256)
    peer_authenticated_executor_capability_required: Literal[True]
    atomic_persistence_authorized: Literal[False]

    @model_validator(mode="after")
    def exact_claim_graph_shape(self) -> Self:
        if (
            type(self.static_role_profile_envelope)
            is not ContainerBootstrapStaticRoleProfileEnvelopeV4
            or type(self.ticket_envelope) is not ContainerAttachTicketEnvelopeV4
            or type(self.expected_runtime) is not ContainerAttachRuntimeBindingV4
            or type(self.preparation) is not ContainerAttachV4ClaimPreparationV4
            or self.replay_receipt_trust_anchor_key_id
            != self.preparation.validation.replay_receipt_trust_anchor_key_id
            or self.replay_receipt_trust_anchor_fingerprint_sha256
            != self.preparation.validation.replay_receipt_trust_anchor_fingerprint_sha256
            or self.peer_authenticated_executor_capability_required is not True
            or self.atomic_persistence_authorized is not False
        ):
            raise ValueError("container attach V4 claim intent is invalid")
        try:
            if len(_canonical_model_bytes(self)) > _MAX_CLAIM_INTENT_BYTES:
                raise ValueError("container attach V4 claim intent is invalid")
        except (RecursionError, TypeError, ValueError):
            raise ValueError("container attach V4 claim intent is invalid") from None
        return self


def container_attach_v4_claim_intent_canonical_json(
    intent: ContainerAttachV4ClaimIntentV4,
) -> bytes:
    """Render an exact value-free V4 future-claim intent, never a bearer request."""

    try:
        canonical = _strict_canonical_model(intent, ContainerAttachV4ClaimIntentV4)
        return _canonical_model_bytes(canonical)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


def parse_container_attach_v4_claim_intent_canonical_json(
    payload: bytes,
) -> ContainerAttachV4ClaimIntentV4:
    """Parse only an exact bounded non-authorizing V4 claim intent."""

    try:
        return _parse_canonical_json(
            payload,
            ContainerAttachV4ClaimIntentV4,
            # This complete graph remains bounded before parsing, but it is
            # never an authority invocation or a delivery capability.
            max_bytes=_MAX_CLAIM_INTENT_BYTES,
        )
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


class ContainerAttachV4ReplayClaimReceiptV4(_Model):
    """Signed evidence of an authority-local atomic V4 claim transaction.

    The receipt's authority timing fields are public metadata only.  They
    attest that the configured replay authority applied its own trusted UTC
    and local monotonic budget inside the transaction that made both replay
    identities unique.  No cross-host monotonic value is serialized.
    """

    schema_version: Literal["rsd.container-attach-replay-claim-receipt.v4"]
    preparation_sha256: str = Field(pattern=_SHA256)
    replay_claim_sha256: str = Field(pattern=_SHA256)
    ticket_replay_claim_sha256: str = Field(pattern=_SHA256)
    container_lifetime_claim_sha256: str = Field(pattern=_SHA256)
    replay_receipt_trust_anchor_key_id: str = Field(pattern=_IDENTIFIER)
    replay_receipt_trust_anchor_fingerprint_sha256: str = Field(pattern=_SHA256)
    state: Literal["claimed_v4"]
    authority_claim_started_at: str
    authority_effective_deadline_at: str
    authority_claim_timeout_seconds: int = Field(ge=1, le=60)
    atomic_deadline_predicate_enforced: Literal[True]
    claimed_at: str
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature_base64: str = Field(min_length=4, max_length=256)

    @field_validator("authority_claim_started_at", "authority_effective_deadline_at", "claimed_at")
    @classmethod
    def canonical_time(cls, value: str) -> str:
        _canonical_timestamp(value)
        return value

    @model_validator(mode="after")
    def exact_atomic_receipt(self) -> Self:
        timing_valid = False
        try:
            authority_started = _canonical_timestamp(self.authority_claim_started_at)
            authority_deadline = _canonical_timestamp(self.authority_effective_deadline_at)
            claimed_at = _canonical_timestamp(self.claimed_at)
            timing_valid = (
                authority_started < authority_deadline
                and authority_started <= claimed_at < authority_deadline
            )
        except ValueError:
            timing_valid = False
        if (
            len(
                {
                    self.preparation_sha256,
                    self.replay_claim_sha256,
                    self.ticket_replay_claim_sha256,
                    self.container_lifetime_claim_sha256,
                }
            )
            != 4
            or len(_canonical_base64_bytes(self.signature_base64)) != 64
            or self.atomic_deadline_predicate_enforced is not True
            or not timing_valid
        ):
            raise ValueError("container attach V4 replay claim receipt is invalid")
        return self


def container_attach_v4_replay_claim_receipt_canonical_message(
    receipt: ContainerAttachV4ReplayClaimReceiptV4,
) -> bytes:
    """Return exact domain-separated V4 receipt bytes without its signature."""

    try:
        canonical = _strict_canonical_model(receipt, ContainerAttachV4ReplayClaimReceiptV4)
        return _REPLAY_RECEIPT_DOMAIN + _canonical_model_bytes(
            canonical, exclude={"signature_base64"}
        )
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


def container_attach_v4_replay_claim_receipt_canonical_json(
    receipt: ContainerAttachV4ReplayClaimReceiptV4,
) -> bytes:
    """Render exact signed V4 external replay-receipt JSON."""

    try:
        canonical = _strict_canonical_model(receipt, ContainerAttachV4ReplayClaimReceiptV4)
        return _canonical_model_bytes(canonical)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


def parse_container_attach_v4_replay_claim_receipt_canonical_json(
    payload: bytes,
) -> ContainerAttachV4ReplayClaimReceiptV4:
    """Parse only exact bounded V4 external replay-receipt JSON."""

    try:
        return _parse_canonical_json(
            payload, ContainerAttachV4ReplayClaimReceiptV4, max_bytes=_MAX_ATTACH_METADATA_BYTES
        )
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


class ContainerAttachV4ReceiptValidationV4(_Model):
    """Repeatable receipt validation with no delivery or effect authority.

    Validating a signed receipt is intentionally not redemption.  A future
    peer-authenticated executor closure must perform durable one-shot receipt
    redemption before it could consume delivery frames.  This model makes the
    current V4 boundary mechanically non-bearer.
    """

    schema_version: Literal["rsd.container-attach-receipt-validation.v4"]
    component: _ComponentV4
    static_role_profile_sha256: str = Field(pattern=_SHA256)
    static_role_profile_envelope_sha256: str = Field(pattern=_SHA256)
    static_profile_trust_anchor_fingerprint_sha256: str = Field(pattern=_SHA256)
    static_delivery_projection_sha256: str = Field(pattern=_SHA256)
    selected_delivery_route_sha256: str = Field(pattern=_SHA256)
    attach_protocol_v4_sha256: str = Field(pattern=_SHA256)
    request_sha256: str = Field(pattern=_SHA256)
    ticket_sha256: str = Field(pattern=_SHA256)
    request_nonce_sha256: str = Field(pattern=_SHA256)
    replay_claim_sha256: str = Field(pattern=_SHA256)
    ticket_replay_claim_sha256: str = Field(pattern=_SHA256)
    container_lifetime_claim_sha256: str = Field(pattern=_SHA256)
    attach_allowed: Literal[False]
    effect_allowed: Literal[False]
    durable_one_shot_receipt_redemption_required: Literal[True]
    peer_authenticated_executor_capability_required: Literal[True]


def _assert_exact_tuple(value: object, expected_element: type[object]) -> None:
    """Reject sequence coercion and every nested model subclass at V4 boundaries."""

    if type(value) is not tuple or any(type(item) is not expected_element for item in value):
        raise ValueError("canonical model is invalid")


def _assert_revalidated_external_model(value: object, expected: type[BaseModel]) -> None:
    """Reject constructed/subclassed imported policy models at a V4 boundary."""

    if type(value) is not expected:
        raise ValueError("canonical model is invalid")
    normalized: BaseModel | None = None
    try:
        normalized = expected.model_validate(value.model_dump(mode="python", warnings="error"))
    except (RecursionError, TypeError, ValueError):
        normalized = None
    if normalized is None or type(normalized) is not expected or normalized != value:
        raise ValueError("canonical model is invalid")


def _assert_exact_static_delivery_field(field: ContainerBootstrapStaticDeliveryFieldV4) -> None:
    """Require exact V4 leaf-field and enum types before canonicalization."""

    if (
        type(field) is not ContainerBootstrapStaticDeliveryFieldV4
        or type(field.value_kind) is not TargetDeliveryValueKindV1
        or type(field.sink) is not ContainerSecretSinkV1
    ):
        raise ValueError("canonical model is invalid")


def _assert_exact_external_policy_tree(value: object) -> None:
    """Check imported V1/V2 static-policy trees before V4 normalization."""

    if type(value) is ContainerAttachTicketTrustAnchorV1:
        _assert_revalidated_external_model(value, ContainerAttachTicketTrustAnchorV1)
        return
    if type(value) is ContainerBootstrapStaticEnvironmentEntryV2:
        _assert_revalidated_external_model(value, ContainerBootstrapStaticEnvironmentEntryV2)
        return
    if type(value) is ContainerBootstrapStaticEnvironmentV2:
        _assert_revalidated_external_model(value, ContainerBootstrapStaticEnvironmentV2)
        _assert_exact_tuple(value.entries, ContainerBootstrapStaticEnvironmentEntryV2)
        for entry in value.entries:
            _assert_exact_external_policy_tree(entry)
        return
    if type(value) is ContainerBootstrapEnvironmentConstructionPolicyV2:
        _assert_revalidated_external_model(value, ContainerBootstrapEnvironmentConstructionPolicyV2)
        _assert_exact_tuple(value.static_entries, ContainerBootstrapStaticEnvironmentEntryV2)
        if type(value.dynamic_target_field_names) is not tuple or any(
            type(item) is not str for item in value.dynamic_target_field_names
        ):
            raise ValueError("canonical model is invalid")
        for entry in value.static_entries:
            _assert_exact_external_policy_tree(entry)
        return
    if type(value) is ContainerBootstrapFdPolicyV2:
        _assert_revalidated_external_model(value, ContainerBootstrapFdPolicyV2)
        return
    if type(value) is ContainerBootstrapPid1PolicyV2:
        _assert_revalidated_external_model(value, ContainerBootstrapPid1PolicyV2)
        if type(value.signal_order) is not tuple or any(
            type(item) is not str for item in value.signal_order
        ):
            raise ValueError("canonical model is invalid")
        return
    if type(value) is ContainerBootstrapMemorySafetyPolicyV2:
        _assert_revalidated_external_model(value, ContainerBootstrapMemorySafetyPolicyV2)
        return
    if type(value) is ContainerBootstrapValkeyLaunchPolicyV2:
        _assert_revalidated_external_model(value, ContainerBootstrapValkeyLaunchPolicyV2)
        sequences = (
            value.command,
            value.acl_denied_command_categories,
            value.static_directive_order,
        )
        if any(
            type(sequence) is not tuple or any(type(item) is not str for item in sequence)
            for sequence in sequences
        ):
            raise ValueError("canonical model is invalid")
        return
    raise ValueError("canonical model is invalid")


def container_bootstrap_static_valkey_launch_policy_v4_sha256(
    policy: ContainerBootstrapValkeyLaunchPolicyV2,
) -> str:
    """Commit the exact V2 Valkey launch policy under a fresh V4 domain.

    This is a source-input commitment only.  It does not claim that a
    container, image, or wrapper output has consumed the policy.
    """

    try:
        _assert_exact_external_policy_tree(policy)
        return _hash(_STATIC_VALKEY_LAUNCH_POLICY_DOMAIN, policy)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("profile")


def _assert_exact_concrete_tree(value: object, expected: type[_Model]) -> None:
    """Reject constructed/subclass/enum/tuple drift recursively for every V4 type."""

    if type(value) is not expected:
        raise ValueError("canonical model is invalid")
    if type(value) is ContainerBootstrapStaticPostgreSQLUriGrammarV4:
        return
    if type(value) is ContainerBootstrapStaticValkeyUriGrammarV4:
        return
    if type(value) is ContainerBootstrapStaticDeliveryFieldV4:
        return
    if type(value) is ContainerBootstrapStaticDeliveryRouteV4:
        _assert_exact_tuple(value.fields, ContainerBootstrapStaticDeliveryFieldV4)
        for field in value.fields:
            _assert_exact_static_delivery_field(field)
        if type(value.sink) is not ContainerSecretSinkV1:
            raise ValueError("canonical model is invalid")
        return
    if type(value) is ContainerBootstrapStaticDeliveryProjectionV4:
        for grammar in (
            value.primary_postgresql_connection_uri,
            value.restore_postgresql_connection_uri,
            value.primary_valkey_connection_uri,
            value.restore_valkey_connection_uri,
        ):
            if type(grammar) is ContainerBootstrapStaticPostgreSQLUriGrammarV4:
                _assert_exact_concrete_tree(grammar, ContainerBootstrapStaticPostgreSQLUriGrammarV4)
            elif type(grammar) is ContainerBootstrapStaticValkeyUriGrammarV4:
                _assert_exact_concrete_tree(grammar, ContainerBootstrapStaticValkeyUriGrammarV4)
            else:
                raise ValueError("canonical model is invalid")
        for route in (
            value.primary_infisical,
            value.primary_valkey,
            value.restore_infisical,
            value.restore_valkey,
        ):
            _assert_exact_concrete_tree(route, ContainerBootstrapStaticDeliveryRouteV4)
        return
    if type(value) is ContainerBootstrapStaticLaunchPlanV4:
        for argv in (value.wrapper_argv_prefix, value.base_entrypoint, value.base_command):
            if type(argv) is not tuple or any(type(item) is not str for item in argv):
                raise ValueError("canonical model is invalid")
        return
    if type(value) is ContainerBootstrapStaticPatchPreimageV4:
        return
    if type(value) is ContainerBootstrapStaticPatchPolicyV4:
        _assert_exact_concrete_tree(value.preimage, ContainerBootstrapStaticPatchPreimageV4)
        return
    if type(value) is ContainerBootstrapAttachProtocolV4:
        if type(value.allowed_operation_scopes) is not tuple or any(
            type(scope) is not str for scope in value.allowed_operation_scopes
        ):
            raise ValueError("canonical model is invalid")
        return
    if type(value) is ContainerBootstrapStaticRoleProfileV4:
        _assert_exact_external_policy_tree(value.ticket_trust_anchor)
        _assert_exact_concrete_tree(
            value.replay_receipt_trust_anchor, ContainerAttachV4ReplayReceiptTrustAnchorV4
        )
        _assert_exact_concrete_tree(value.attach_protocol, ContainerBootstrapAttachProtocolV4)
        _assert_exact_concrete_tree(
            value.static_delivery_projection, ContainerBootstrapStaticDeliveryProjectionV4
        )
        _assert_exact_concrete_tree(
            value.selected_delivery_route, ContainerBootstrapStaticDeliveryRouteV4
        )
        _assert_exact_concrete_tree(value.static_launch_plan, ContainerBootstrapStaticLaunchPlanV4)
        _assert_exact_concrete_tree(
            value.static_patch_preimage, ContainerBootstrapStaticPatchPreimageV4
        )
        _assert_exact_concrete_tree(
            value.static_patch_policy, ContainerBootstrapStaticPatchPolicyV4
        )
        _assert_exact_external_policy_tree(value.static_environment)
        _assert_exact_external_policy_tree(value.child_environment_policy)
        _assert_exact_external_policy_tree(value.fd_policy)
        _assert_exact_external_policy_tree(value.pid1_policy)
        _assert_exact_external_policy_tree(value.memory_safety_policy)
        if value.valkey_launch_policy is not None:
            _assert_exact_external_policy_tree(value.valkey_launch_policy)
        return
    if type(value) is ContainerBootstrapStaticProfileTrustAnchorV4:
        return
    if type(value) is ContainerBootstrapStaticRoleProfileEnvelopeV4:
        _assert_exact_concrete_tree(
            value.static_role_profile, ContainerBootstrapStaticRoleProfileV4
        )
        return
    if type(value) is ContainerAttachRuntimeBindingV4:
        return
    if type(value) is ContainerAttachRequestV4:
        _assert_exact_tuple(value.fields, ContainerBootstrapStaticDeliveryFieldV4)
        for field in value.fields:
            _assert_exact_static_delivery_field(field)
        return
    if type(value) is ContainerAttachAuthorizationTicketV4:
        return
    if type(value) is ContainerAttachTicketEnvelopeV4:
        _assert_exact_concrete_tree(value.request, ContainerAttachRequestV4)
        _assert_exact_concrete_tree(value.ticket, ContainerAttachAuthorizationTicketV4)
        return
    if type(value) is ContainerAttachV4TicketValidation:
        return
    if type(value) is ContainerAttachV4ClaimDeadlineV4:
        return
    if type(value) is ContainerAttachV4TicketReplayClaimV4:
        return
    if type(value) is ContainerAttachV4ContainerLifetimeClaimV4:
        return
    if type(value) is ContainerAttachV4ReplayClaimV4:
        _assert_exact_concrete_tree(value.ticket_claim, ContainerAttachV4TicketReplayClaimV4)
        _assert_exact_concrete_tree(
            value.container_lifetime_claim, ContainerAttachV4ContainerLifetimeClaimV4
        )
        return
    if type(value) is ContainerAttachV4ReplayReceiptTrustAnchorV4:
        return
    if type(value) is ContainerAttachV4ClaimPreparationV4:
        _assert_exact_concrete_tree(value.validation, ContainerAttachV4TicketValidation)
        _assert_exact_concrete_tree(value.replay_claim, ContainerAttachV4ReplayClaimV4)
        _assert_exact_concrete_tree(value.claim_deadline, ContainerAttachV4ClaimDeadlineV4)
        return
    if type(value) is ContainerAttachV4ClaimIntentV4:
        _assert_exact_concrete_tree(
            value.static_role_profile_envelope, ContainerBootstrapStaticRoleProfileEnvelopeV4
        )
        _assert_exact_concrete_tree(value.ticket_envelope, ContainerAttachTicketEnvelopeV4)
        _assert_exact_concrete_tree(value.expected_runtime, ContainerAttachRuntimeBindingV4)
        _assert_exact_concrete_tree(value.preparation, ContainerAttachV4ClaimPreparationV4)
        return
    if type(value) is ContainerAttachV4ReplayClaimReceiptV4:
        return
    if type(value) is ContainerAttachV4ReceiptValidationV4:
        return
    raise ValueError("canonical model is invalid")


def _runtime_binding_matches_request(
    binding: ContainerAttachRuntimeBindingV4,
    request: ContainerAttachRequestV4,
) -> bool:
    """Compare exact target-local runtime facts before a future frame boundary."""

    return (
        binding.allocation_operation_id == request.allocation_operation_id
        and binding.operation_scope == request.operation_scope
        and binding.operation_id == request.operation_id
        and binding.component == request.component
        and binding.component_role == request.component_role
        and binding.container_id == request.container_id
        and binding.runtime_hostname == request.runtime_hostname
        and binding.runtime_instance_binding_sha256 == request.runtime_instance_binding_sha256
        and binding.request_nonce_sha256 == request.request_nonce_sha256
        and binding.channel_binding_sha256 == request.channel_binding_sha256
        and binding.session_binding_sha256 == request.session_binding_sha256
    )


def _require_ticket_fresh(
    *, issued_at: str, expires_at: str, max_ticket_lifetime_seconds: int
) -> tuple[datetime, datetime, datetime]:
    """Check exclusive expiry with the module-local trusted UTC boundary."""

    issued = _canonical_timestamp(issued_at)
    expires = _canonical_timestamp(expires_at)
    now = _trusted_now()
    if (
        now < issued
        or now >= expires
        or expires - issued > timedelta(seconds=max_ticket_lifetime_seconds)
    ):
        _fail("freshness")
    return now, issued, expires


def validate_container_attach_v4_ticket(
    *,
    static_role_profile_envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4,
    profile_trust_anchor: ContainerBootstrapStaticProfileTrustAnchorV4,
    envelope: ContainerAttachTicketEnvelopeV4,
    expected_runtime: ContainerAttachRuntimeBindingV4,
) -> ContainerAttachV4TicketValidation:
    """Purely validate a V4 ticket before any future frame could be consumed.

    This phase is not authorization and returns no delivery capability. A
    future target must bind this graph to an independently authenticated
    executor channel and durably redeem an exact receipt before it could
    consider metadata usable.  V4 provides neither that channel nor a replay
    persistence adapter.
    """

    profile: ContainerBootstrapStaticRoleProfileV4 | None = None
    profile_envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4 | None = None
    canonical_profile_trust_anchor: ContainerBootstrapStaticProfileTrustAnchorV4 | None = None
    canonical_envelope: ContainerAttachTicketEnvelopeV4 | None = None
    runtime: ContainerAttachRuntimeBindingV4 | None = None
    try:
        profile_envelope = strict_canonical_container_bootstrap_static_role_profile_envelope_v4(
            static_role_profile_envelope
        )
        canonical_profile_trust_anchor = (
            strict_canonical_container_bootstrap_static_profile_trust_anchor_v4(
                profile_trust_anchor
            )
        )
        profile = verify_container_bootstrap_static_role_profile_envelope_v4(
            envelope=profile_envelope,
            profile_trust_anchor=canonical_profile_trust_anchor,
        )
        canonical_envelope = _strict_canonical_model(envelope, ContainerAttachTicketEnvelopeV4)
        runtime = _strict_canonical_model(expected_runtime, ContainerAttachRuntimeBindingV4)
    except (ContainerAttachStaticV4Error, RecursionError, TypeError, ValueError):
        pass
    if (
        profile is None
        or profile_envelope is None
        or canonical_profile_trust_anchor is None
        or canonical_envelope is None
        or runtime is None
    ):
        _fail("binding")

    request = canonical_envelope.request
    ticket = canonical_envelope.ticket
    protocol = profile.attach_protocol
    projection = profile.static_delivery_projection
    route = profile.selected_delivery_route
    metadata_bytes: bytes | None = None
    try:
        metadata_bytes = _canonical_model_bytes(canonical_envelope)
    except (RecursionError, TypeError, ValueError):
        metadata_bytes = None
    if metadata_bytes is None or len(metadata_bytes) > protocol.max_metadata_bytes:
        _fail("ticket")
    commitments: tuple[str, str, str, str, str, str, str] | None = None
    try:
        profile_sha256 = container_bootstrap_static_role_profile_v4_sha256(profile)
        projection_sha256 = container_bootstrap_static_delivery_projection_v4_sha256(projection)
        route_sha256 = container_bootstrap_static_delivery_route_v4_sha256(route)
        protocol_sha256 = container_bootstrap_attach_v4_protocol_sha256(protocol)
        request_sha256 = container_attach_v4_request_sha256(request)
        ticket_sha256 = container_attach_v4_ticket_sha256(ticket)
        profile_envelope_sha256 = container_bootstrap_static_role_profile_envelope_v4_sha256(
            profile_envelope
        )
        commitments = (
            profile_sha256,
            profile_envelope_sha256,
            projection_sha256,
            route_sha256,
            protocol_sha256,
            request_sha256,
            ticket_sha256,
        )
    except ContainerAttachStaticV4Error:
        pass
    if commitments is None:
        _fail("profile")
    (
        profile_sha256,
        profile_envelope_sha256,
        projection_sha256,
        route_sha256,
        protocol_sha256,
        request_sha256,
        ticket_sha256,
    ) = commitments

    if not (
        request.component == profile.component
        and request.component_role == profile.component_role
        and request.static_role_profile_sha256 == profile_sha256
        and request.static_role_profile_envelope_sha256 == profile_envelope_sha256
        and request.static_profile_trust_anchor_fingerprint_sha256
        == canonical_profile_trust_anchor.public_key_fingerprint_sha256
        and request.replay_receipt_trust_anchor_key_id == profile.replay_receipt_trust_anchor.key_id
        and request.replay_receipt_trust_anchor_fingerprint_sha256
        == profile.replay_receipt_trust_anchor.public_key_fingerprint_sha256
        and request.static_delivery_projection_sha256 == projection_sha256
        and request.selected_delivery_route_sha256 == route_sha256
        and request.attach_protocol_v4_sha256 == protocol_sha256
        and request.fields == route.fields
        and _runtime_binding_matches_request(runtime, request)
    ):
        _fail("binding")

    freshness_checked_at, _, _ = _require_ticket_fresh(
        issued_at=ticket.issued_at,
        expires_at=ticket.expires_at,
        max_ticket_lifetime_seconds=protocol.max_ticket_lifetime_seconds,
    )
    anchor = profile.ticket_trust_anchor
    signature_valid = False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            _canonical_base64_bytes(anchor.public_key_base64)
        )
        public_key.verify(
            _canonical_base64_bytes(ticket.signature_base64),
            _ATTACH_TICKET_DOMAIN + _canonical_model_bytes(ticket, exclude={"signature_base64"}),
        )
        signature_valid = ticket.signer_key_id == anchor.key_id and anchor.algorithm == "ed25519"
    except (InvalidSignature, ValueError):
        signature_valid = False
    if not signature_valid:
        _fail("signature")

    return ContainerAttachV4TicketValidation(
        schema_version="rsd.container-attach-ticket-validation.v4",
        component=profile.component,
        component_role=profile.component_role,
        static_role_profile_sha256=profile_sha256,
        static_role_profile_envelope_sha256=profile_envelope_sha256,
        static_profile_trust_anchor_fingerprint_sha256=(
            canonical_profile_trust_anchor.public_key_fingerprint_sha256
        ),
        replay_receipt_trust_anchor_key_id=profile.replay_receipt_trust_anchor.key_id,
        replay_receipt_trust_anchor_fingerprint_sha256=(
            profile.replay_receipt_trust_anchor.public_key_fingerprint_sha256
        ),
        static_delivery_projection_sha256=projection_sha256,
        selected_delivery_route_sha256=route_sha256,
        attach_protocol_v4_sha256=protocol_sha256,
        request_sha256=request_sha256,
        ticket_sha256=ticket_sha256,
        request_nonce_sha256=request.request_nonce_sha256,
        channel_binding_sha256=request.channel_binding_sha256,
        session_binding_sha256=request.session_binding_sha256,
        allocation_operation_id=request.allocation_operation_id,
        operation_scope=request.operation_scope,
        operation_id=request.operation_id,
        container_id=request.container_id,
        runtime_hostname=request.runtime_hostname,
        runtime_instance_binding_sha256=request.runtime_instance_binding_sha256,
        freshness_checked_at=_canonical_timestamp_text(freshness_checked_at),
        issued_at=ticket.issued_at,
        expires_at=ticket.expires_at,
        claim_timeout_seconds=protocol.claim_timeout_seconds,
        max_ticket_lifetime_seconds=protocol.max_ticket_lifetime_seconds,
    )


def _replay_claim_from_validation(
    validation: ContainerAttachV4TicketValidation,
) -> ContainerAttachV4ReplayClaimV4:
    """Derive both required V4 atomic replay identities from one validation."""

    return ContainerAttachV4ReplayClaimV4(
        schema_version="rsd.container-attach-replay-claim.v4",
        ticket_claim=ContainerAttachV4TicketReplayClaimV4(
            schema_version="rsd.container-attach-ticket-replay-claim.v4",
            static_role_profile_sha256=validation.static_role_profile_sha256,
            static_role_profile_envelope_sha256=(validation.static_role_profile_envelope_sha256),
            static_profile_trust_anchor_fingerprint_sha256=(
                validation.static_profile_trust_anchor_fingerprint_sha256
            ),
            request_sha256=validation.request_sha256,
            ticket_sha256=validation.ticket_sha256,
            allocation_operation_id=validation.allocation_operation_id,
            operation_scope=validation.operation_scope,
            operation_id=validation.operation_id,
            component=validation.component,
            component_role=validation.component_role,
            container_id=validation.container_id,
            runtime_hostname=validation.runtime_hostname,
            runtime_instance_binding_sha256=validation.runtime_instance_binding_sha256,
            request_nonce_sha256=validation.request_nonce_sha256,
            channel_binding_sha256=validation.channel_binding_sha256,
            session_binding_sha256=validation.session_binding_sha256,
        ),
        container_lifetime_claim=ContainerAttachV4ContainerLifetimeClaimV4(
            schema_version="rsd.container-attach-container-lifetime-claim.v4",
            container_id=validation.container_id,
            one_attach_per_container_lifetime=True,
        ),
    )


def _claim_deadline_from_validation(
    validation: ContainerAttachV4TicketValidation,
) -> ContainerAttachV4ClaimDeadlineV4:
    """Derive authority-side UTC cutoff and local-budget policy from a ticket."""

    deadline: ContainerAttachV4ClaimDeadlineV4 | None = None
    try:
        expires_at = _canonical_timestamp(validation.expires_at)
        deadline = ContainerAttachV4ClaimDeadlineV4(
            schema_version="rsd.container-attach-claim-deadline.v4",
            ticket_sha256=validation.ticket_sha256,
            ticket_expires_at=validation.expires_at,
            effective_deadline_at=_canonical_timestamp_text(expires_at),
            claim_timeout_seconds=validation.claim_timeout_seconds,
            atomic_deadline_predicate_required=True,
            authority_local_monotonic_budget_required=True,
        )
    except (RecursionError, TypeError, ValueError):
        deadline = None
    if deadline is None:
        _fail("freshness")
    return deadline


def prepare_container_attach_v4_claim_intent(
    *,
    static_role_profile_envelope: ContainerBootstrapStaticRoleProfileEnvelopeV4,
    profile_trust_anchor: ContainerBootstrapStaticProfileTrustAnchorV4,
    envelope: ContainerAttachTicketEnvelopeV4,
    expected_runtime: ContainerAttachRuntimeBindingV4,
) -> ContainerAttachV4ClaimIntentV4:
    """Prepare a non-bearer V4 intent for a future authenticated executor.

    This function does not invoke an authority, persist a replay key, consume
    a frame, or return a delivery capability.  Serializing the result cannot
    authorize an atomic claim: V4 deliberately lacks the independently
    observed peer-authenticated executor channel required for that operation.
    """

    try:
        canonical_profile_envelope = (
            strict_canonical_container_bootstrap_static_role_profile_envelope_v4(
                static_role_profile_envelope
            )
        )
        canonical_envelope = _strict_canonical_model(envelope, ContainerAttachTicketEnvelopeV4)
        canonical_runtime = _strict_canonical_model(
            expected_runtime, ContainerAttachRuntimeBindingV4
        )
    except (ContainerAttachStaticV4Error, RecursionError, TypeError, ValueError):
        _fail("binding")
    validation = validate_container_attach_v4_ticket(
        static_role_profile_envelope=canonical_profile_envelope,
        profile_trust_anchor=profile_trust_anchor,
        envelope=canonical_envelope,
        expected_runtime=canonical_runtime,
    )
    preparation = build_container_attach_v4_claim_preparation(
        validation=validation,
        claim_deadline=_claim_deadline_from_validation(validation),
    )
    try:
        return ContainerAttachV4ClaimIntentV4(
            schema_version="rsd.container-attach-claim-intent.v4",
            static_role_profile_envelope=canonical_profile_envelope,
            ticket_envelope=canonical_envelope,
            expected_runtime=canonical_runtime,
            preparation=preparation,
            replay_receipt_trust_anchor_key_id=(
                preparation.validation.replay_receipt_trust_anchor_key_id
            ),
            replay_receipt_trust_anchor_fingerprint_sha256=(
                preparation.validation.replay_receipt_trust_anchor_fingerprint_sha256
            ),
            peer_authenticated_executor_capability_required=True,
            atomic_persistence_authorized=False,
        )
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


def _strict_canonical_container_attach_v4_claim_preparation(
    preparation: ContainerAttachV4ClaimPreparationV4,
) -> ContainerAttachV4ClaimPreparationV4:
    """Return one exact V4 preparation or a fixed replay failure."""

    try:
        return _strict_canonical_model(preparation, ContainerAttachV4ClaimPreparationV4)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


def _strict_canonical_container_attach_v4_replay_receipt_anchor(
    anchor: ContainerAttachV4ReplayReceiptTrustAnchorV4,
) -> ContainerAttachV4ReplayReceiptTrustAnchorV4:
    """Return one exact V4 receipt root or a fixed replay failure."""

    try:
        return _strict_canonical_model(anchor, ContainerAttachV4ReplayReceiptTrustAnchorV4)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


def _strict_canonical_container_attach_v4_replay_receipt(
    receipt: ContainerAttachV4ReplayClaimReceiptV4,
) -> ContainerAttachV4ReplayClaimReceiptV4:
    """Return one exact V4 external receipt or a fixed replay failure."""

    try:
        return _strict_canonical_model(receipt, ContainerAttachV4ReplayClaimReceiptV4)
    except (RecursionError, TypeError, ValueError):
        pass
    _fail("replay")


def _verify_replay_receipt_signature(
    *,
    receipt: ContainerAttachV4ReplayClaimReceiptV4,
    trust_anchor: ContainerAttachV4ReplayReceiptTrustAnchorV4,
) -> None:
    """Verify an external receipt without preserving a collaborator error chain."""

    signature_valid = False
    try:
        if receipt.signer_key_id != trust_anchor.key_id:
            raise ValueError("replay receipt signer is invalid")
        key = Ed25519PublicKey.from_public_bytes(
            _canonical_base64_bytes(trust_anchor.public_key_base64)
        )
        key.verify(
            _canonical_base64_bytes(receipt.signature_base64),
            container_attach_v4_replay_claim_receipt_canonical_message(receipt),
        )
        signature_valid = True
    except (ContainerAttachStaticV4Error, InvalidSignature, ValueError):
        signature_valid = False
    if not signature_valid:
        _fail("replay")


def _same_validation_identity(
    first: ContainerAttachV4TicketValidation,
    second: ContainerAttachV4TicketValidation,
) -> bool:
    """Compare every stable validation binding while allowing a new UTC sample."""

    return first.model_dump(exclude={"freshness_checked_at"}) == second.model_dump(
        exclude={"freshness_checked_at"}
    )


def _require_authority_claim_deadline_binding(
    *,
    preparation: ContainerAttachV4ClaimPreparationV4,
    validation: ContainerAttachV4TicketValidation,
) -> None:
    """Bind authority commit policy to the freshly verified signed graph.

    This verifier deliberately does not compare a caller's monotonic value to
    an authority's clock.  The external authority must instead apply the
    profile-bound timeout with its own local monotonic interval as an atomic
    storage predicate, and attest that predicate in its signed receipt.
    """

    deadline = preparation.claim_deadline
    if (
        deadline.ticket_sha256 != validation.ticket_sha256
        or deadline.ticket_expires_at != validation.expires_at
        or deadline.effective_deadline_at != validation.expires_at
        or deadline.claim_timeout_seconds != validation.claim_timeout_seconds
        or deadline.atomic_deadline_predicate_required is not True
        or deadline.authority_local_monotonic_budget_required is not True
    ):
        _fail("replay")


def _verify_container_attach_v4_claim_intent(
    *,
    intent: ContainerAttachV4ClaimIntentV4,
    profile_trust_anchor: ContainerBootstrapStaticProfileTrustAnchorV4,
) -> tuple[
    ContainerAttachV4ClaimPreparationV4,
    ContainerAttachV4TicketValidation,
    ContainerBootstrapStaticRoleProfileV4,
]:
    """Revalidate a complete signed graph for receipt validation only.

    This internal helper cannot invoke persistence.  The external profile root
    remains a verifier input, while the receipt root is recovered only from
    the profile whose envelope that root has authenticated.
    """

    canonical_intent: ContainerAttachV4ClaimIntentV4 | None = None
    try:
        canonical_intent = _strict_canonical_model(intent, ContainerAttachV4ClaimIntentV4)
    except (RecursionError, TypeError, ValueError):
        canonical_intent = None
    if canonical_intent is None:
        _fail("replay")
    canonical_preparation = _strict_canonical_container_attach_v4_claim_preparation(
        canonical_intent.preparation
    )
    validation = validate_container_attach_v4_ticket(
        static_role_profile_envelope=canonical_intent.static_role_profile_envelope,
        profile_trust_anchor=profile_trust_anchor,
        envelope=canonical_intent.ticket_envelope,
        expected_runtime=canonical_intent.expected_runtime,
    )
    profile = verify_container_bootstrap_static_role_profile_envelope_v4(
        envelope=canonical_intent.static_role_profile_envelope,
        profile_trust_anchor=profile_trust_anchor,
    )
    prepared_validation = canonical_preparation.validation
    if not _same_validation_identity(prepared_validation, validation):
        _fail("freshness")
    expected_claim = _replay_claim_from_validation(validation)
    if (
        canonical_preparation.replay_claim != expected_claim
        or canonical_preparation.replay_claim_sha256
        != container_attach_v4_replay_claim_sha256(expected_claim)
        or canonical_preparation.ticket_replay_claim_sha256
        != container_attach_v4_ticket_replay_claim_sha256(expected_claim.ticket_claim)
        or canonical_preparation.container_lifetime_claim_sha256
        != container_attach_v4_container_lifetime_claim_sha256(
            expected_claim.container_lifetime_claim
        )
    ):
        _fail("replay")
    _require_authority_claim_deadline_binding(
        preparation=canonical_preparation, validation=validation
    )
    if (
        canonical_intent.replay_receipt_trust_anchor_key_id
        != profile.replay_receipt_trust_anchor.key_id
        or canonical_intent.replay_receipt_trust_anchor_fingerprint_sha256
        != profile.replay_receipt_trust_anchor.public_key_fingerprint_sha256
        or canonical_intent.peer_authenticated_executor_capability_required is not True
        or canonical_intent.atomic_persistence_authorized is not False
    ):
        _fail("replay")
    return canonical_preparation, validation, profile


def _local_finalization_deadline_from_validation(
    validation: ContainerAttachV4TicketValidation,
) -> tuple[datetime, datetime, int]:
    """Derive one verifier-local UTC/monotonic finalization budget."""

    try:
        started_at = _canonical_timestamp(validation.freshness_checked_at)
        expires_at = _canonical_timestamp(validation.expires_at)
        deadline_at = min(
            expires_at, started_at + timedelta(seconds=validation.claim_timeout_seconds)
        )
        budget_seconds = int((deadline_at - started_at).total_seconds())
    except (TypeError, ValueError):
        _fail("freshness")
    if budget_seconds < 1:
        _fail("freshness")
    return started_at, deadline_at, budget_seconds


def _require_authority_receipt_timing(
    *,
    receipt: ContainerAttachV4ReplayClaimReceiptV4,
    validation: ContainerAttachV4TicketValidation,
) -> None:
    """Require signed evidence of the authority's atomic local deadline predicate."""

    try:
        issued_at = _canonical_timestamp(validation.issued_at)
        ticket_expires_at = _canonical_timestamp(validation.expires_at)
        authority_started_at = _canonical_timestamp(receipt.authority_claim_started_at)
        authority_deadline_at = _canonical_timestamp(receipt.authority_effective_deadline_at)
        claimed_at = _canonical_timestamp(receipt.claimed_at)
        expected_authority_deadline = min(
            ticket_expires_at,
            authority_started_at + timedelta(seconds=validation.claim_timeout_seconds),
        )
    except (TypeError, ValueError):
        _fail("freshness")
    if (
        receipt.authority_claim_timeout_seconds != validation.claim_timeout_seconds
        or receipt.atomic_deadline_predicate_enforced is not True
        or authority_started_at < issued_at
        or authority_started_at >= ticket_expires_at
        or authority_deadline_at != expected_authority_deadline
        or claimed_at < authority_started_at
        or claimed_at >= authority_deadline_at
    ):
        _fail("freshness")


def validate_container_attach_v4_claim_receipt(
    *,
    claim_intent: ContainerAttachV4ClaimIntentV4,
    profile_trust_anchor: ContainerBootstrapStaticProfileTrustAnchorV4,
    receipt: ContainerAttachV4ReplayClaimReceiptV4,
) -> ContainerAttachV4ReceiptValidationV4:
    """Validate a signed receipt without redeeming it or enabling any effect.

    This revalidates raw signed profile/ticket/runtime inputs, uses only the
    distinct receipt root embedded in the externally authenticated profile,
    and checks authority-local receipt timing plus a verifier-local freshness
    budget.  It neither invokes nor exposes a replay authority and returns a
    mechanically non-bearer result: attach/effect remain false until a future
    peer-authenticated executor performs durable one-shot redemption.
    """

    finalization_monotonic_started = _read_trusted_monotonic_now()
    canonical_receipt = _strict_canonical_container_attach_v4_replay_receipt(receipt)
    canonical_preparation, validation, profile = _verify_container_attach_v4_claim_intent(
        intent=claim_intent,
        profile_trust_anchor=profile_trust_anchor,
    )
    finalization_started_at, finalization_deadline_at, finalization_budget_seconds = (
        _local_finalization_deadline_from_validation(validation)
    )
    expected_claim = _replay_claim_from_validation(validation)
    expected_claim_sha256 = container_attach_v4_replay_claim_sha256(expected_claim)
    expected_ticket_claim_sha256 = container_attach_v4_ticket_replay_claim_sha256(
        expected_claim.ticket_claim
    )
    expected_lifetime_claim_sha256 = container_attach_v4_container_lifetime_claim_sha256(
        expected_claim.container_lifetime_claim
    )
    if (
        canonical_preparation.replay_claim != expected_claim
        or canonical_preparation.replay_claim_sha256 != expected_claim_sha256
        or canonical_preparation.ticket_replay_claim_sha256 != expected_ticket_claim_sha256
        or canonical_preparation.container_lifetime_claim_sha256 != expected_lifetime_claim_sha256
        or canonical_receipt.preparation_sha256 != canonical_preparation.preparation_sha256
        or canonical_receipt.replay_claim_sha256 != expected_claim_sha256
        or canonical_receipt.ticket_replay_claim_sha256 != expected_ticket_claim_sha256
        or canonical_receipt.container_lifetime_claim_sha256 != expected_lifetime_claim_sha256
        or canonical_receipt.replay_receipt_trust_anchor_key_id
        != profile.replay_receipt_trust_anchor.key_id
        or canonical_receipt.replay_receipt_trust_anchor_fingerprint_sha256
        != profile.replay_receipt_trust_anchor.public_key_fingerprint_sha256
    ):
        _fail("replay")
    _verify_replay_receipt_signature(
        receipt=canonical_receipt, trust_anchor=profile.replay_receipt_trust_anchor
    )
    _require_authority_receipt_timing(receipt=canonical_receipt, validation=validation)
    post_utc, _, _ = _require_ticket_fresh(
        issued_at=validation.issued_at,
        expires_at=validation.expires_at,
        max_ticket_lifetime_seconds=validation.max_ticket_lifetime_seconds,
    )
    if post_utc < finalization_started_at or post_utc >= finalization_deadline_at:
        _fail("freshness")
    post_monotonic = _read_trusted_monotonic_now()
    if (
        post_monotonic < finalization_monotonic_started
        or post_monotonic >= finalization_monotonic_started + float(finalization_budget_seconds)
    ):
        _fail("freshness")
    return ContainerAttachV4ReceiptValidationV4(
        schema_version="rsd.container-attach-receipt-validation.v4",
        component=validation.component,
        static_role_profile_sha256=validation.static_role_profile_sha256,
        static_role_profile_envelope_sha256=validation.static_role_profile_envelope_sha256,
        static_profile_trust_anchor_fingerprint_sha256=(
            validation.static_profile_trust_anchor_fingerprint_sha256
        ),
        static_delivery_projection_sha256=validation.static_delivery_projection_sha256,
        selected_delivery_route_sha256=validation.selected_delivery_route_sha256,
        attach_protocol_v4_sha256=validation.attach_protocol_v4_sha256,
        request_sha256=validation.request_sha256,
        ticket_sha256=validation.ticket_sha256,
        request_nonce_sha256=validation.request_nonce_sha256,
        replay_claim_sha256=expected_claim_sha256,
        ticket_replay_claim_sha256=expected_ticket_claim_sha256,
        container_lifetime_claim_sha256=expected_lifetime_claim_sha256,
        attach_allowed=False,
        effect_allowed=False,
        durable_one_shot_receipt_redemption_required=True,
        peer_authenticated_executor_capability_required=True,
    )
