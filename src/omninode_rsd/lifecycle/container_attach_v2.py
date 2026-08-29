"""Contract-only V2 local daemon-to-container attach framing.

V2 is intentionally separate from :mod:`container_attach`, which preserves the
existing V1 contract.  This module has no lifecycle backend and never creates a
container, reads a provider, renders a URI, starts a workload, or persists a
secret.  It defines the only future local attach boundary that may carry a
value: a signed ticket envelope, ordered binary chunks, an actual write
half-close, a terminal acknowledgement after input EOF, and protocol-output
EOF.

The raw Unix Docker adapter is deliberately a narrow transport seam.  It is
not wired into ``NoMutationBackend`` or an executor effect.  Production use is
blocked until a separately reviewed materialization/start backend supplies
sealed artifacts and installation evidence.
"""

from __future__ import annotations

import json
import math
import socket
import struct
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Final, Literal, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ValidationError

from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerAttachAuthorizationTicketV1,
    ContainerAttachCheckpointV2,
    ContainerAttachClaimV2,
    ContainerAttachReadyV2,
    ContainerAttachReceiptV2,
    ContainerAttachTerminalAckV2,
    ContainerAttachTicketEnvelopeV2,
    ContainerAttachTicketTrustAnchorV1,
    ContainerAttachV2AuthorizationPolicyV1,
    ContainerBootstrapAttachProtocolV1,
    ContainerBootstrapAttachProtocolV2,
    ContainerBootstrapInspectionV2,
    ContainerBootstrapTemplateV1,
    ContainerBootstrapTemplateV2,
    ContainerBootstrapWrapperArtifactV1,
    ContainerBootstrapWrapperArtifactV2,
    ContainerBootstrapWrapperManifestV1,
    ContainerBootstrapWrapperManifestV2,
    ContainerTargetDeliveryV1,
    DockerContainerAttachControlPolicyV2,
    MaterializationComponentPlanV1,
    MaterializationIntentV1,
    TargetDeliveryFieldV1,
    TargetDeliveryMapV1,
    _canonical_base64_bytes,
    _strict_canonical_model,
    canonical_sha256,
    container_attach_authorization_ticket_message,
    container_attach_authorization_ticket_sha256,
    container_attach_chunk_descriptors_sha256,
    container_attach_runtime_instance_binding_sha256,
    container_attach_v2_ack_sha256,
    container_attach_v2_authorization_policy_message,
    container_attach_v2_authorization_policy_sha256,
    container_attach_v2_request_sha256,
    container_bootstrap_attach_protocol_sha256,
    container_bootstrap_attach_v2_protocol_message,
    container_bootstrap_attach_v2_protocol_sha256,
    container_bootstrap_v2_inspection_matches,
    container_bootstrap_wrapper_manifest_sha256,
    container_bootstrap_wrapper_v2_manifest_message,
    container_bootstrap_wrapper_v2_manifest_sha256,
    docker_container_attach_v2_control_policy_message,
    docker_container_attach_v2_control_policy_sha256,
    materialization_intent_sha256,
    target_delivery_map_sha256,
)

_MAGIC: Final = b"ONC2"
_FRAME_VERSION: Final = 2
_HEADER: Final = struct.Struct("!4sBBI")
_HEADER_BYTES: Final = _HEADER.size
_CHUNK_ORDINAL: Final = struct.Struct("!H")
_DOCKER_MUX_HEADER: Final = struct.Struct("!BxxxI")
_DOCKER_MUX_HEADER_BYTES: Final = _DOCKER_MUX_HEADER.size
_BASE64URL_ALPHABET: Final = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_BASE64URL_INDEX: Final = {value: index for index, value in enumerate(_BASE64URL_ALPHABET)}
_DEADLINE_CAPABILITY: Final = object()
_VERIFIED_AUTHORIZATION_CAPABILITY: Final = object()
_V1_WRAPPER_MANIFEST_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.container-wrapper-manifest.ed25519.v1\x00"
)
_V1_TARGET_DELIVERY_MAP_SIGNATURE_DOMAIN: Final = b"omninode-rsd.target-delivery-map.ed25519.v1\x00"
_V1_ATTACH_PROTOCOL_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.container-attach-protocol.ed25519.v1\x00"
)
_V1_MATERIALIZATION_INTENT_SIGNATURE_DOMAIN: Final = (
    b"omninode-rsd.materialization-intent.ed25519.v1\x00"
)
_PHASES: Final[frozenset[str]] = frozenset(
    {
        "ack",
        "authorization",
        "attach_endpoint",
        "attach_handshake",
        "attach_policy",
        "attach_protocol",
        "attach_request",
        "claim",
        "deadline",
        "eof",
        "frame_header",
        "frame_payload",
        "frame_size",
        "frame_write",
        "metadata",
        "nonce_authority",
        "ready",
        "replay",
        "secret_chunk",
        "secret_chunks",
        "state",
        "target_sink",
        "ticket",
        "ticket_authority",
        "ticket_envelope",
        "write_close",
    }
)


class ContainerAttachV2Error(RuntimeError):
    """Detached, value-redacted V2 attach failure."""

    def __init__(self, phase: str) -> None:
        canonical = phase if type(phase) is str and phase in _PHASES else "authorization"
        self.phase = canonical
        super().__init__(f"container attach V2 failed at phase: {canonical}")


def _fresh_error(phase: str) -> ContainerAttachV2Error:
    """Create a boundary error after any hostile exception scope has ended."""

    error = ContainerAttachV2Error(phase)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


class ContainerAttachV2FrameType(IntEnum):
    """The closed directional V2 frame set."""

    TICKET_ENVELOPE = 1
    READY = 2
    CLAIM = 3
    SECRET_CHUNK = 4
    TERMINAL_ACK = 5


class ContainerAttachV2SessionState(StrEnum):
    """Monotonic session states; rejected/ambiguous are terminal."""

    NEW = "new"
    TICKET_SENT = "ticket_sent"
    READY_RECEIVED = "ready_received"
    CLAIM_SENT = "claim_sent"
    CLAIM_ATTEMPTED = "claim_attempted"
    CHUNKS_SENT = "chunks_sent"
    WRITE_CLOSED = "write_closed"
    TERMINAL_ACK_RECEIVED = "terminal_ack_received"
    CLOSED = "closed"
    REJECTED = "rejected"
    AMBIGUOUS = "ambiguous"


class ContainerAttachV2WriteCloseResult(StrEnum):
    """The sole valid result after a real underlying write half-close."""

    HALF_CLOSED = "half_closed"


class ContainerAttachV2OutputCloseResult(StrEnum):
    """The sole valid wrapper-side result after closing protocol stdout."""

    OUTPUT_CLOSED = "output_closed"


class ContainerAttachV2TicketClaimResult(StrEnum):
    """The only outcomes of durable ticket/nonce consumption."""

    CLAIMED = "claimed"
    REPLAYED = "replayed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ContainerAttachV2TicketClaimV1:
    """Value-free ticket identity that must be consumed before chunk delivery."""

    boundary: str
    ticket_sha256: str
    request_sha256: str
    allocation_operation_id: str
    operation_id: str
    component: str
    container_id: str
    request_nonce_sha256: str
    target_delivery_map_sha256: str


@dataclass(frozen=True, slots=True)
class ContainerAttachV2ContainerLifetimeClaimV1:
    """Separate durable uniqueness key for one immutable Docker container ID.

    A fresh ticket, nonce, channel, or session does not create another attach
    entitlement for the same container.  A future durable authority must make
    this claim and the ticket claim atomically unique before any claim frame or
    secret chunk can be emitted.
    """

    boundary: Literal["daemon_send_v2"]
    allocation_operation_id: str
    operation_id: str
    component: str
    container_id: str
    one_attach_per_container_lifetime: Literal[True]


class ContainerAttachV2TicketAuthority(Protocol):
    """Atomic ticket-and-container replay authority required before delivery."""

    def claim_ticket_and_container_once(
        self,
        ticket_claim: ContainerAttachV2TicketClaimV1,
        container_lifetime_claim: ContainerAttachV2ContainerLifetimeClaimV1,
        *,
        deadline: ContainerAttachV2Deadline,
    ) -> ContainerAttachV2TicketClaimResult: ...


class ContainerAttachV2MonotonicClock(Protocol):
    """A future adapter must provide an actual monotonic deadline source."""

    def monotonic(self) -> float: ...


class ContainerAttachV2DeadlineReader(Protocol):
    """Bounded reader; production adapters must enforce the opaque deadline."""

    def read(self, count: int, *, deadline: ContainerAttachV2Deadline) -> bytes: ...


class ContainerAttachV2DeadlineWriter(Protocol):
    """Bounded writer; production adapters must enforce the opaque deadline."""

    def write(
        self,
        data: bytes | bytearray | memoryview,
        *,
        deadline: ContainerAttachV2Deadline,
    ) -> object: ...


class ContainerAttachV2Duplex(
    ContainerAttachV2DeadlineReader, ContainerAttachV2DeadlineWriter, Protocol
):
    """Duplex contract with a mandatory, non-noop sender half-close."""

    def close_write(
        self, *, deadline: ContainerAttachV2Deadline
    ) -> ContainerAttachV2WriteCloseResult: ...


class ContainerAttachV2OutputCloser(Protocol):
    """Wrapper output FD close after the terminal acknowledgement."""

    def close_output(
        self, *, deadline: ContainerAttachV2Deadline
    ) -> ContainerAttachV2OutputCloseResult: ...


class ContainerAttachV2SecretSink(Protocol):
    """The only wrapper capability allowed to see one mutable chunk briefly."""

    def accept(self, descriptor: TargetDeliveryFieldV1, value: memoryview) -> None: ...


def _zeroize(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _zeroize_discoverable_buffers(value: object, *, _seen: set[int] | None = None) -> None:
    """Scrub built-in mutable buffers in rejected shapes without iterating callbacks."""

    seen = set() if _seen is None else _seen
    identity = id(value)
    if identity in seen:
        return
    seen.add(identity)
    if type(value) is bytearray:
        _zeroize(value)
        return
    if type(value) is memoryview:
        try:
            view = cast(memoryview, value)
            if not view.readonly and view.c_contiguous:
                bytes_view = view.cast("B")
                for index in range(len(bytes_view)):
                    bytes_view[index] = 0
        except (TypeError, ValueError):
            pass
        return
    if type(value) in {list, tuple}:
        for item in cast(list[object] | tuple[object, ...], value):
            _zeroize_discoverable_buffers(item, _seen=seen)
        return
    if type(value) is dict:
        for key, item in cast(dict[object, object], value).items():
            _zeroize_discoverable_buffers(key, _seen=seen)
            _zeroize_discoverable_buffers(item, _seen=seen)


def _valid_monotonic(value: object) -> bool:
    return type(value) is float and math.isfinite(value) and value >= 0.0


class _MonotonicGuard:
    __slots__ = ("_clock", "_last")

    def __init__(self, clock: ContainerAttachV2MonotonicClock) -> None:
        self._clock = clock
        self._last: float | None = None

    def now(self, *, phase: str) -> float:
        failed = False
        result = 0.0
        try:
            result = self._clock.monotonic()
        except Exception:
            failed = True
        if (
            failed
            or not _valid_monotonic(result)
            or (self._last is not None and result < self._last)
        ):
            raise _fresh_error(phase)
        self._last = result
        return result


class ContainerAttachV2Deadline:
    """Opaque deadline capability issued only by this module's state machine."""

    __slots__ = ("__expires_at", "__guard")

    def __init__(self, guard: _MonotonicGuard, expires_at: float, *, capability: object) -> None:
        if capability is not _DEADLINE_CAPABILITY:
            raise TypeError("container attach V2 deadline is internally issued")
        self.__guard = guard
        self.__expires_at = expires_at

    def _issued_by(self, guard: _MonotonicGuard) -> bool:
        return self.__guard is guard

    def remaining_seconds(self) -> float:
        now = self.__guard.now(phase="deadline")
        if now >= self.__expires_at:
            raise _fresh_error("deadline")
        remaining = self.__expires_at - now
        if not _valid_monotonic(remaining) or remaining <= 0.0:
            raise _fresh_error("deadline")
        return remaining

    def _bounded(self, seconds: int, *, phase: str) -> ContainerAttachV2Deadline:
        """Issue a phase deadline that cannot outlive this absolute deadline."""

        if type(seconds) is not int or seconds < 1:
            raise _fresh_error(phase)
        now = self.__guard.now(phase=phase)
        phase_expires_at = now + float(seconds)
        expires_at = min(phase_expires_at, self.__expires_at)
        if (
            not _valid_monotonic(phase_expires_at)
            or not _valid_monotonic(expires_at)
            or expires_at <= now
        ):
            raise _fresh_error(phase)
        return ContainerAttachV2Deadline(self.__guard, expires_at, capability=_DEADLINE_CAPABILITY)


def _deadline(guard: _MonotonicGuard, seconds: int, *, phase: str) -> ContainerAttachV2Deadline:
    if type(seconds) is not int or seconds < 1:
        raise _fresh_error(phase)
    now = guard.now(phase=phase)
    expires_at = now + float(seconds)
    if not _valid_monotonic(expires_at) or expires_at <= now:
        raise _fresh_error(phase)
    return ContainerAttachV2Deadline(guard, expires_at, capability=_DEADLINE_CAPABILITY)


def _phase_deadline(
    guard: _MonotonicGuard,
    absolute_deadline: ContainerAttachV2Deadline,
    seconds: int,
    *,
    phase: str,
) -> ContainerAttachV2Deadline:
    """Derive a bounded phase deadline from a session-wide absolute budget."""

    result: ContainerAttachV2Deadline | None = None
    failed = False
    try:
        if type(
            absolute_deadline
        ) is not ContainerAttachV2Deadline or not absolute_deadline._issued_by(guard):
            raise ValueError
        result = absolute_deadline._bounded(seconds, phase=phase)
    except Exception:
        failed = True
    if failed or result is None:
        raise _fresh_error(phase)
    return result


def _require_before(
    guard: _MonotonicGuard, deadline: ContainerAttachV2Deadline, *, phase: str
) -> None:
    failed = False
    try:
        if type(deadline) is not ContainerAttachV2Deadline or not deadline._issued_by(guard):
            raise ValueError
        deadline.remaining_seconds()
    except Exception:
        failed = True
    if failed:
        raise _fresh_error(phase)


def _canonical_metadata(model: BaseModel) -> bytes:
    rendered = b""
    failed = False
    try:
        rendered = json.dumps(
            model.model_dump(mode="json", warnings="error"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except Exception:
        failed = True
    if failed:
        raise _fresh_error("metadata")
    return rendered


def _same_exact_shape(original: object, canonical: object) -> bool:
    if type(original) is not type(canonical):
        return False
    if isinstance(original, BaseModel):
        return (
            isinstance(canonical, BaseModel)
            and type(original) is type(canonical)
            and all(
                _same_exact_shape(getattr(original, name), getattr(canonical, name))
                for name in original.__class__.model_fields
            )
        )
    if type(original) is tuple:
        canonical_tuple = cast(tuple[object, ...], canonical)
        return len(original) == len(canonical_tuple) and all(
            _same_exact_shape(left, right)
            for left, right in zip(original, canonical_tuple, strict=True)
        )
    if type(original) is list:
        canonical_list = cast(list[object], canonical)
        return len(original) == len(canonical_list) and all(
            _same_exact_shape(left, right)
            for left, right in zip(original, canonical_list, strict=True)
        )
    if type(original) is dict:
        canonical_dict = cast(dict[object, object], canonical)
        return len(original) == len(canonical_dict) and all(
            _same_exact_shape(key, right_key)
            and _same_exact_shape(original[key], canonical_dict[right_key])
            for key, right_key in zip(original, canonical_dict, strict=True)
        )
    return original == canonical


def _strict_model[ModelType: BaseModel](
    model: object, model_type: type[ModelType], *, phase: str
) -> ModelType:
    if type(model) is not model_type:
        raise _fresh_error(phase)
    canonical: ModelType | None = None
    original = b""
    rendered = b""
    failed = False
    try:
        original = _canonical_metadata(cast(BaseModel, model))
        canonical = model_type.model_validate_json(original, strict=True)
        rendered = _canonical_metadata(canonical)
    except Exception:
        failed = True
    if (
        failed
        or canonical is None
        or type(canonical) is not model_type
        or original != rendered
        or not _same_exact_shape(model, canonical)
    ):
        raise _fresh_error(phase)
    return canonical


def _read_exact(
    reader: ContainerAttachV2DeadlineReader,
    guard: _MonotonicGuard,
    deadline: ContainerAttachV2Deadline,
    count: int,
    *,
    mutable: bool,
    phase: str,
) -> bytes | bytearray:
    if type(count) is not int or count < 0:
        raise _fresh_error(phase)
    result = bytearray()
    failed = False
    try:
        while len(result) < count:
            _require_before(guard, deadline, phase=phase)
            block = reader.read(count - len(result), deadline=deadline)
            _require_before(guard, deadline, phase=phase)
            if type(block) is not bytes or not block or len(block) > count - len(result):
                raise ValueError
            result.extend(block)
    except Exception:
        failed = True
    if failed:
        _zeroize(result)
        raise _fresh_error(phase)
    if mutable:
        return result
    rendered = bytes(result)
    _zeroize(result)
    return rendered


def _write(
    writer: ContainerAttachV2DeadlineWriter,
    guard: _MonotonicGuard,
    deadline: ContainerAttachV2Deadline,
    data: bytes | bytearray | memoryview,
    *,
    phase: str,
) -> None:
    written: object = None
    failed = False
    try:
        _require_before(guard, deadline, phase=phase)
        written = writer.write(data, deadline=deadline)
        _require_before(guard, deadline, phase=phase)
    except Exception:
        failed = True
    if failed or type(written) is not int or written != len(data):
        raise _fresh_error(phase)


def _write_frame(
    writer: ContainerAttachV2DeadlineWriter,
    guard: _MonotonicGuard,
    deadline: ContainerAttachV2Deadline,
    *,
    protocol: ContainerBootstrapAttachProtocolV2,
    frame_type: ContainerAttachV2FrameType,
    payload: bytes | bytearray | memoryview,
    secret: bool,
) -> None:
    limit = (
        protocol.max_chunk_bytes + _CHUNK_ORDINAL.size if secret else protocol.max_metadata_bytes
    )
    if len(payload) > limit:
        raise _fresh_error("frame_size")
    header = _HEADER.pack(_MAGIC, _FRAME_VERSION, int(frame_type), len(payload))
    _write(writer, guard, deadline, header, phase="frame_write")
    _write(writer, guard, deadline, payload, phase="frame_write")


def _read_frame(
    reader: ContainerAttachV2DeadlineReader,
    guard: _MonotonicGuard,
    deadline: ContainerAttachV2Deadline,
    *,
    protocol: ContainerBootstrapAttachProtocolV2,
    expected_type: ContainerAttachV2FrameType,
    secret: bool,
) -> bytes | bytearray:
    header = _read_exact(
        reader, guard, deadline, _HEADER_BYTES, mutable=False, phase="frame_header"
    )
    failed = False
    magic = b""
    version = -1
    raw_type = -1
    length = -1
    frame_type: ContainerAttachV2FrameType | None = None
    try:
        magic, version, raw_type, length = _HEADER.unpack(cast(bytes, header))
        frame_type = ContainerAttachV2FrameType(raw_type)
    except Exception:
        failed = True
    if failed or frame_type is None:
        raise _fresh_error("frame_header")
    limit = (
        protocol.max_chunk_bytes + _CHUNK_ORDINAL.size if secret else protocol.max_metadata_bytes
    )
    if (
        magic != _MAGIC
        or version != _FRAME_VERSION
        or frame_type is not expected_type
        or length > limit
    ):
        raise _fresh_error("frame_header")
    return _read_exact(reader, guard, deadline, length, mutable=secret, phase="frame_payload")


def _read_metadata[ModelType: BaseModel](
    reader: ContainerAttachV2DeadlineReader,
    guard: _MonotonicGuard,
    deadline: ContainerAttachV2Deadline,
    *,
    protocol: ContainerBootstrapAttachProtocolV2,
    frame_type: ContainerAttachV2FrameType,
    model_type: type[ModelType],
    phase: str,
) -> ModelType:
    raw = _read_frame(
        reader,
        guard,
        deadline,
        protocol=protocol,
        expected_type=frame_type,
        secret=False,
    )
    model: ModelType | None = None
    failed = False
    try:
        model = model_type.model_validate_json(cast(bytes, raw), strict=True)
        if _canonical_metadata(model) != raw:
            raise ValueError
    except Exception:
        failed = True
    if failed or model is None:
        raise _fresh_error(phase)
    return _strict_model(model, model_type, phase=phase)


def _read_secret_chunk(
    reader: ContainerAttachV2DeadlineReader,
    guard: _MonotonicGuard,
    deadline: ContainerAttachV2Deadline,
    *,
    protocol: ContainerBootstrapAttachProtocolV2,
    expected_ordinal: int,
) -> bytearray:
    payload = _read_frame(
        reader,
        guard,
        deadline,
        protocol=protocol,
        expected_type=ContainerAttachV2FrameType.SECRET_CHUNK,
        secret=True,
    )
    buffer = cast(bytearray, payload)
    failed = False
    try:
        if len(buffer) < _CHUNK_ORDINAL.size:
            raise ValueError
        ordinal = _CHUNK_ORDINAL.unpack(bytes(buffer[: _CHUNK_ORDINAL.size]))[0]
        if ordinal != expected_ordinal:
            raise ValueError
        for index in range(_CHUNK_ORDINAL.size):
            buffer[index] = 0
        del buffer[: _CHUNK_ORDINAL.size]
    except Exception:
        failed = True
    if failed:
        _zeroize(buffer)
        raise _fresh_error("secret_chunk")
    return buffer


def _write_secret_frame(
    writer: ContainerAttachV2DeadlineWriter,
    guard: _MonotonicGuard,
    deadline: ContainerAttachV2Deadline,
    *,
    protocol: ContainerBootstrapAttachProtocolV2,
    ordinal: int,
    chunk: bytearray,
) -> None:
    if not 1 <= ordinal <= protocol.max_chunks_per_target or len(chunk) > protocol.max_chunk_bytes:
        raise _fresh_error("secret_chunk")
    header = _HEADER.pack(
        _MAGIC,
        _FRAME_VERSION,
        int(ContainerAttachV2FrameType.SECRET_CHUNK),
        _CHUNK_ORDINAL.size + len(chunk),
    )
    _write(writer, guard, deadline, header, phase="frame_write")
    _write(writer, guard, deadline, _CHUNK_ORDINAL.pack(ordinal), phase="frame_write")
    _write(writer, guard, deadline, memoryview(chunk), phase="frame_write")


def _require_valkey_requirepass_grammar(
    descriptor: TargetDeliveryFieldV1,
    buffer: bytearray,
    *,
    authorization: _VerifiedContainerAttachV2Authorization,
) -> None:
    """Validate the one Valkey dynamic directive without materializing its value."""

    policy = authorization.template.valkey_launch_policy
    expected_purpose = (
        "primary_valkey_password"
        if authorization.envelope.request.component == "primary_valkey"
        else "restore_valkey_password"
    )
    raw_count = 0
    failed = False
    try:
        if (
            policy is None
            or descriptor.target_field != policy.requirepass_dynamic_directive
            or descriptor.source_purpose != expected_purpose
            or descriptor.value_kind.value != "direct_provider_material_v1"
            or descriptor.format != "valkey_password_base64url_32_v1"
            or descriptor.sink.value != "valkey_stdin_configuration_v1"
            or policy.requirepass_raw_byte_count != 32
            or policy.requirepass_canonical_base64url_unpadded is not True
            or policy.requirepass_directive_count != 1
        ):
            raise ValueError
        raw_count = policy.requirepass_raw_byte_count
        encoded_count = 4 * ((raw_count + 2) // 3) - ((3 - raw_count % 3) % 3)
        if len(buffer) != encoded_count or descriptor.encoded_byte_count != encoded_count:
            raise ValueError
        if any(value not in _BASE64URL_INDEX for value in buffer):
            raise ValueError
        final_value = _BASE64URL_INDEX[buffer[-1]]
        remainder = raw_count % 3
        if (remainder == 1 and final_value & 0x0F) or (remainder == 2 and final_value & 0x03):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        failed = True
    if failed:
        raise _fresh_error("secret_chunk")


def _require_secret_delivery_grammar(
    descriptor: TargetDeliveryFieldV1,
    buffer: bytearray,
    *,
    authorization: _VerifiedContainerAttachV2Authorization,
) -> None:
    """Apply exact component-local grammar before any sink sees secret bytes."""

    if authorization.envelope.request.component.endswith("valkey"):
        _require_valkey_requirepass_grammar(descriptor, buffer, authorization=authorization)


def _trusted_utc_now() -> datetime:
    """The V2 verifier's internal production clock boundary."""

    return datetime.now(UTC)


def _trusted_now(*, phase: str) -> datetime:
    now: datetime | None = None
    failed = False
    try:
        now = _trusted_utc_now()
    except Exception:
        failed = True
    if failed or type(now) is not datetime or now.tzinfo is None:
        raise _fresh_error(phase)
    return now.astimezone(UTC)


def _require_authorization_fresh(
    *,
    policy: ContainerAttachV2AuthorizationPolicyV1,
    ticket: ContainerAttachAuthorizationTicketV1,
    materialization_intent: MaterializationIntentV1,
    phase: str,
) -> None:
    """Recheck every retained signed authority at its actual use boundary."""

    now = _trusted_now(phase=phase)
    policy_created: datetime | None = None
    policy_expires: datetime | None = None
    ticket_issued: datetime | None = None
    ticket_expires: datetime | None = None
    materialization_created: datetime | None = None
    materialization_retention_expires: datetime | None = None
    failed = False
    try:
        policy_created = datetime.fromisoformat(policy.created_at.removesuffix("Z") + "+00:00")
        policy_expires = datetime.fromisoformat(policy.expires_at.removesuffix("Z") + "+00:00")
        ticket_issued = datetime.fromisoformat(ticket.issued_at.removesuffix("Z") + "+00:00")
        ticket_expires = datetime.fromisoformat(ticket.expires_at.removesuffix("Z") + "+00:00")
        materialization_created = datetime.fromisoformat(
            materialization_intent.created_at.removesuffix("Z") + "+00:00"
        )
        materialization_retention_expires = datetime.fromisoformat(
            materialization_intent.retention_expires_at.removesuffix("Z") + "+00:00"
        )
    except (AttributeError, TypeError, ValueError):
        failed = True
    if (
        failed
        or policy_created is None
        or policy_expires is None
        or ticket_issued is None
        or ticket_expires is None
        or materialization_created is None
        or materialization_retention_expires is None
    ):
        raise _fresh_error(phase)
    lifetime = ticket_expires - ticket_issued
    if (
        policy_created.astimezone(UTC) > now
        or policy_expires.astimezone(UTC) <= now
        or ticket_issued.astimezone(UTC) > now
        or ticket_expires.astimezone(UTC) <= now
        or lifetime.total_seconds() > policy.ticket_max_lifetime_seconds
        or materialization_created.astimezone(UTC) > now
        or materialization_retention_expires.astimezone(UTC) <= now
    ):
        raise _fresh_error(phase)


def _verify_signature(
    model: BaseModel,
    *,
    trust_anchor: ContainerAttachTicketTrustAnchorV1,
    message: Callable[[BaseModel], bytes],
    phase: str,
) -> None:
    signer_key_id = getattr(model, "signer_key_id", None)
    signature_base64 = getattr(model, "signature_base64", None)
    failed = False
    try:
        checked_anchor = _strict_model(
            trust_anchor, ContainerAttachTicketTrustAnchorV1, phase=phase
        )
        if type(signer_key_id) is not str or signer_key_id != checked_anchor.key_id:
            raise ValueError
        if type(signature_base64) is not str:
            raise ValueError
        signature = _canonical_base64_bytes(signature_base64)
        if len(signature) != 64:
            raise ValueError
        public_key = _strict_canonical_model(
            checked_anchor, ContainerAttachTicketTrustAnchorV1
        ).public_key_base64
        key_bytes = _canonical_base64_bytes(public_key)
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature, message(model))
    except (InvalidSignature, ValueError, TypeError, ValidationError):
        failed = True
    if failed:
        raise _fresh_error(phase)


def _v1_direct_signature_message(domain: bytes, model: BaseModel) -> bytes:
    """Render an existing V1 direct-signature preimage without importing its effect layer."""

    if type(domain) is not bytes or not domain.endswith(b"\x00"):
        raise _fresh_error("authorization")
    rendered = b""
    failed = False
    try:
        material = model.model_dump(mode="json", exclude={"signature_base64"}, warnings="error")
        rendered = domain + json.dumps(material, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    except Exception:
        failed = True
    if failed:
        raise _fresh_error("authorization")
    return rendered


def _verify_v1_predecessor_chain(
    *,
    trust_anchor: ContainerAttachTicketTrustAnchorV1,
    wrapper_manifest: ContainerBootstrapWrapperManifestV1,
    target_delivery_map: TargetDeliveryMapV1,
    attach_protocol: ContainerBootstrapAttachProtocolV1,
) -> tuple[
    ContainerBootstrapWrapperManifestV1,
    TargetDeliveryMapV1,
    ContainerBootstrapAttachProtocolV1,
]:
    """Verify the V1 signed artifacts that V2 replaces only at its local boundary."""

    checked_wrapper_manifest = _strict_model(
        wrapper_manifest, ContainerBootstrapWrapperManifestV1, phase="authorization"
    )
    checked_target_delivery_map = _strict_model(
        target_delivery_map, TargetDeliveryMapV1, phase="authorization"
    )
    checked_attach_protocol = _strict_model(
        attach_protocol, ContainerBootstrapAttachProtocolV1, phase="authorization"
    )
    _verify_signature(
        checked_wrapper_manifest,
        trust_anchor=trust_anchor,
        message=lambda item: _v1_direct_signature_message(
            _V1_WRAPPER_MANIFEST_SIGNATURE_DOMAIN,
            cast(ContainerBootstrapWrapperManifestV1, item),
        ),
        phase="authorization",
    )
    _verify_signature(
        checked_target_delivery_map,
        trust_anchor=trust_anchor,
        message=lambda item: _v1_direct_signature_message(
            _V1_TARGET_DELIVERY_MAP_SIGNATURE_DOMAIN,
            cast(TargetDeliveryMapV1, item),
        ),
        phase="authorization",
    )
    _verify_signature(
        checked_attach_protocol,
        trust_anchor=trust_anchor,
        message=lambda item: _v1_direct_signature_message(
            _V1_ATTACH_PROTOCOL_SIGNATURE_DOMAIN,
            cast(ContainerBootstrapAttachProtocolV1, item),
        ),
        phase="authorization",
    )
    return checked_wrapper_manifest, checked_target_delivery_map, checked_attach_protocol


def _component_target(
    delivery_map: TargetDeliveryMapV1, component: str
) -> ContainerTargetDeliveryV1:
    targets = {
        "primary_infisical": delivery_map.primary_infisical,
        "primary_valkey": delivery_map.primary_valkey,
        "restore_infisical": delivery_map.restore_infisical,
        "restore_valkey": delivery_map.restore_valkey,
    }
    try:
        return targets[component]
    except (KeyError, TypeError):
        raise _fresh_error("authorization") from None


def _component_artifact(
    manifest: ContainerBootstrapWrapperManifestV2, component: str
) -> ContainerBootstrapWrapperArtifactV2:
    artifacts = {
        "primary_infisical": manifest.primary_infisical,
        "primary_valkey": manifest.primary_valkey,
        "restore_infisical": manifest.restore_infisical,
        "restore_valkey": manifest.restore_valkey,
    }
    try:
        return artifacts[component]
    except (KeyError, TypeError):
        raise _fresh_error("authorization") from None


def _component_v1_artifact(
    manifest: ContainerBootstrapWrapperManifestV1, component: str
) -> ContainerBootstrapWrapperArtifactV1:
    """Return the exact V1 immutable wrapper artifact for one target."""

    artifacts = {
        "primary_infisical": manifest.primary_infisical,
        "primary_valkey": manifest.primary_valkey,
        "restore_infisical": manifest.restore_infisical,
        "restore_valkey": manifest.restore_valkey,
    }
    try:
        return artifacts[component]
    except (KeyError, TypeError):
        raise _fresh_error("authorization") from None


def _component_v1_template(
    materialization_intent: MaterializationIntentV1, component: str
) -> ContainerBootstrapTemplateV1:
    templates = {
        "primary_infisical": materialization_intent.bootstrap_templates.primary_infisical,
        "primary_valkey": materialization_intent.bootstrap_templates.primary_valkey,
        "restore_infisical": materialization_intent.bootstrap_templates.restore_infisical,
        "restore_valkey": materialization_intent.bootstrap_templates.restore_valkey,
    }
    try:
        return templates[component]
    except (KeyError, TypeError):
        raise _fresh_error("authorization") from None


def _component_materialization_plan(
    materialization_intent: MaterializationIntentV1, component: str
) -> MaterializationComponentPlanV1:
    components = {
        "primary_infisical": materialization_intent.plan.primary_infisical,
        "primary_valkey": materialization_intent.plan.primary_valkey,
        "restore_infisical": materialization_intent.plan.restore_infisical,
        "restore_valkey": materialization_intent.plan.restore_valkey,
    }
    try:
        return components[component]
    except (KeyError, TypeError):
        raise _fresh_error("authorization") from None


def _v2_template_matches_materialization_predecessor(
    *,
    template: ContainerBootstrapTemplateV2,
    artifact: ContainerBootstrapWrapperArtifactV2,
    v1_template: ContainerBootstrapTemplateV1,
    component_plan: MaterializationComponentPlanV1,
) -> bool:
    """Require V2 create fields to refine, never replace, the V1 plan."""

    if (
        template.image != artifact.derived_image_policy.image
        or template.image_policy != artifact.derived_image_policy
        or template.image != v1_template.image
        or template.image_policy != v1_template.image_policy
        or template.network_name != v1_template.network_name
        or template.network_alias != v1_template.network_alias
        or template.static_ipv4 != v1_template.static_ipv4
        or template.accepted_secret_sink != v1_template.accepted_secret_sink
    ):
        return False
    is_valkey = template.component.endswith("valkey")
    if not is_valkey:
        return (
            template.mounts == ()
            and v1_template.mounts == ()
            and component_plan.volume_name is None
        )
    if len(template.mounts) != 1 or len(v1_template.mounts) != 1:
        return False
    v2_mount = template.mounts[0]
    v1_mount = v1_template.mounts[0]
    return (
        component_plan.volume_name is not None
        and v2_mount.source_volume_name == component_plan.volume_name
        and v2_mount.source_volume_name == v1_mount.source_volume_name
        and v2_mount.mount_type == v1_mount.mount_type
        and v2_mount.target_path == v1_mount.target_path
        and v2_mount.bind_allowed == v1_mount.bind_allowed
        and v2_mount.tmpfs_allowed == v1_mount.tmpfs_allowed
        and v2_mount.propagation == v1_mount.propagation
    )


def _v2_artifact_matches_v1_predecessor(
    *,
    artifact: ContainerBootstrapWrapperArtifactV2,
    v1_artifact: ContainerBootstrapWrapperArtifactV1,
    v1_template: ContainerBootstrapTemplateV1,
) -> bool:
    """Bind one V2 wrapper profile to its exact immutable V1 predecessor."""

    return (
        artifact.component == v1_artifact.component == v1_template.component
        and artifact.v1_wrapper_artifact_binding_sha256 == v1_artifact.artifact_binding_sha256
        and artifact.base_image_policy == v1_artifact.base_image_policy
        and artifact.derived_image_policy == v1_artifact.derived_image_policy
        and v1_template.wrapper_artifact_binding_sha256 == v1_artifact.artifact_binding_sha256
        and v1_template.image == v1_artifact.derived_image_policy.image
        and v1_template.image_policy == v1_artifact.derived_image_policy
    )


@dataclass(frozen=True, slots=True, init=False)
class _VerifiedContainerAttachV2Authorization:
    """Unforgeable-in-normal-use value-free result of V2 verification.

    The public constructor is deliberately unavailable.  Only the verifier
    below holds the internal issuance capability, so a caller-supplied bundle
    cannot reach a ticket claim or an attach socket merely by constructing a
    convenient dataclass.
    """

    policy: ContainerAttachV2AuthorizationPolicyV1
    protocol: ContainerBootstrapAttachProtocolV2
    wrapper_manifest: ContainerBootstrapWrapperManifestV2
    target_delivery_map: TargetDeliveryMapV1
    v1_wrapper_manifest: ContainerBootstrapWrapperManifestV1
    v1_attach_protocol: ContainerBootstrapAttachProtocolV1
    materialization_intent: MaterializationIntentV1
    docker_attach_policy: DockerContainerAttachControlPolicyV2
    template: ContainerBootstrapTemplateV2
    inspection: ContainerBootstrapInspectionV2
    envelope: ContainerAttachTicketEnvelopeV2
    policy_sha256: str

    def __init__(self, **_: object) -> None:
        raise TypeError("verified container attach V2 authorization is internally issued")

    @classmethod
    def _issue(
        cls,
        *,
        capability: object,
        policy: ContainerAttachV2AuthorizationPolicyV1,
        protocol: ContainerBootstrapAttachProtocolV2,
        wrapper_manifest: ContainerBootstrapWrapperManifestV2,
        target_delivery_map: TargetDeliveryMapV1,
        v1_wrapper_manifest: ContainerBootstrapWrapperManifestV1,
        v1_attach_protocol: ContainerBootstrapAttachProtocolV1,
        materialization_intent: MaterializationIntentV1,
        docker_attach_policy: DockerContainerAttachControlPolicyV2,
        template: ContainerBootstrapTemplateV2,
        inspection: ContainerBootstrapInspectionV2,
        envelope: ContainerAttachTicketEnvelopeV2,
        policy_sha256: str,
    ) -> _VerifiedContainerAttachV2Authorization:
        if capability is not _VERIFIED_AUTHORIZATION_CAPABILITY:
            raise TypeError("verified container attach V2 authorization is internally issued")
        issued = object.__new__(cls)
        for name, value in (
            ("policy", policy),
            ("protocol", protocol),
            ("wrapper_manifest", wrapper_manifest),
            ("target_delivery_map", target_delivery_map),
            ("v1_wrapper_manifest", v1_wrapper_manifest),
            ("v1_attach_protocol", v1_attach_protocol),
            ("materialization_intent", materialization_intent),
            ("docker_attach_policy", docker_attach_policy),
            ("template", template),
            ("inspection", inspection),
            ("envelope", envelope),
            ("policy_sha256", policy_sha256),
        ):
            object.__setattr__(issued, name, value)
        return issued


def verify_container_attach_v2_authorization(
    *,
    policy: ContainerAttachV2AuthorizationPolicyV1,
    protocol: ContainerBootstrapAttachProtocolV2,
    wrapper_manifest: ContainerBootstrapWrapperManifestV2,
    target_delivery_map: TargetDeliveryMapV1,
    v1_wrapper_manifest: ContainerBootstrapWrapperManifestV1,
    v1_attach_protocol: ContainerBootstrapAttachProtocolV1,
    materialization_intent: MaterializationIntentV1,
    docker_attach_policy: DockerContainerAttachControlPolicyV2,
    template: ContainerBootstrapTemplateV2,
    inspection: ContainerBootstrapInspectionV2,
    envelope: ContainerAttachTicketEnvelopeV2,
    trust_anchor: ContainerAttachTicketTrustAnchorV1,
) -> _VerifiedContainerAttachV2Authorization:
    """Verify all V2 bindings before a future attach can be attempted.

    This is an in-memory verifier only.  A future executor must load these
    signed artifacts descriptor-relatively and claim the ticket in a durable
    journal before it calls any secret-capable session method.
    """

    checked_policy = _strict_model(
        policy, ContainerAttachV2AuthorizationPolicyV1, phase="authorization"
    )
    checked_protocol = _strict_model(
        protocol, ContainerBootstrapAttachProtocolV2, phase="authorization"
    )
    checked_manifest = _strict_model(
        wrapper_manifest, ContainerBootstrapWrapperManifestV2, phase="authorization"
    )
    checked_map = _strict_model(target_delivery_map, TargetDeliveryMapV1, phase="authorization")
    checked_materialization_intent = _strict_model(
        materialization_intent, MaterializationIntentV1, phase="authorization"
    )
    checked_docker_attach_policy = _strict_model(
        docker_attach_policy, DockerContainerAttachControlPolicyV2, phase="authorization"
    )
    checked_template = _strict_model(template, ContainerBootstrapTemplateV2, phase="authorization")
    checked_inspection = _strict_model(
        inspection, ContainerBootstrapInspectionV2, phase="authorization"
    )
    checked_envelope = _strict_model(
        envelope, ContainerAttachTicketEnvelopeV2, phase="ticket_envelope"
    )
    checked_anchor = _strict_model(
        trust_anchor, ContainerAttachTicketTrustAnchorV1, phase="authorization"
    )
    (
        checked_v1_wrapper_manifest,
        checked_v1_target_delivery_map,
        checked_v1_attach_protocol,
    ) = _verify_v1_predecessor_chain(
        trust_anchor=checked_anchor,
        wrapper_manifest=v1_wrapper_manifest,
        target_delivery_map=checked_map,
        attach_protocol=v1_attach_protocol,
    )
    _verify_signature(
        checked_policy,
        trust_anchor=checked_anchor,
        message=lambda item: container_attach_v2_authorization_policy_message(
            cast(ContainerAttachV2AuthorizationPolicyV1, item)
        ),
        phase="authorization",
    )
    _verify_signature(
        checked_protocol,
        trust_anchor=checked_anchor,
        message=lambda item: container_bootstrap_attach_v2_protocol_message(
            cast(ContainerBootstrapAttachProtocolV2, item)
        ),
        phase="authorization",
    )
    _verify_signature(
        checked_manifest,
        trust_anchor=checked_anchor,
        message=lambda item: container_bootstrap_wrapper_v2_manifest_message(
            cast(ContainerBootstrapWrapperManifestV2, item)
        ),
        phase="authorization",
    )
    _verify_signature(
        checked_docker_attach_policy,
        trust_anchor=checked_anchor,
        message=lambda item: docker_container_attach_v2_control_policy_message(
            cast(DockerContainerAttachControlPolicyV2, item)
        ),
        phase="authorization",
    )
    _verify_signature(
        checked_materialization_intent,
        trust_anchor=checked_anchor,
        message=lambda item: _v1_direct_signature_message(
            _V1_MATERIALIZATION_INTENT_SIGNATURE_DOMAIN,
            cast(MaterializationIntentV1, item),
        ),
        phase="authorization",
    )
    _verify_signature(
        checked_envelope.ticket,
        trust_anchor=checked_anchor,
        message=lambda item: container_attach_authorization_ticket_message(
            cast(ContainerAttachAuthorizationTicketV1, item)
        ),
        phase="ticket",
    )
    ticket = checked_envelope.ticket
    request = checked_envelope.request
    _require_authorization_fresh(
        policy=checked_policy,
        ticket=ticket,
        materialization_intent=checked_materialization_intent,
        phase="ticket",
    )
    if checked_policy.ticket_trust_anchor != checked_anchor:
        raise _fresh_error("ticket")
    protocol_sha = container_bootstrap_attach_v2_protocol_sha256(checked_protocol)
    manifest_sha = container_bootstrap_wrapper_v2_manifest_sha256(checked_manifest)
    map_sha = target_delivery_map_sha256(checked_map)
    v1_wrapper_manifest_sha = container_bootstrap_wrapper_manifest_sha256(
        checked_v1_wrapper_manifest
    )
    v1_attach_protocol_sha = container_bootstrap_attach_protocol_sha256(checked_v1_attach_protocol)
    materialization_sha = materialization_intent_sha256(checked_materialization_intent)
    policy_sha = container_attach_v2_authorization_policy_sha256(checked_policy)
    artifact = _component_artifact(checked_manifest, request.component)
    v1_artifact = _component_v1_artifact(checked_v1_wrapper_manifest, request.component)
    v1_template = _component_v1_template(checked_materialization_intent, request.component)
    component_plan = _component_materialization_plan(
        checked_materialization_intent, request.component
    )
    target = _component_target(checked_map, request.component)
    target_fields = target.fields
    target_derived_image_sha = target.derived_image_policy_sha256
    target_wrapper_binding = target.wrapper_artifact_binding_sha256
    target_protocol_sha = target.attach_protocol_sha256
    wrapper_profile_sha = canonical_sha256(artifact)
    total_secret_bytes = sum(field.encoded_byte_count for field in request.fields)
    placements = {
        "primary_infisical": checked_map.topology.primary_infisical,
        "primary_valkey": checked_map.topology.primary_valkey,
        "restore_infisical": checked_map.topology.restore_infisical,
        "restore_valkey": checked_map.topology.restore_valkey,
    }
    expected_placement = placements[request.component]
    valkey_static_addresses = {
        "primary_valkey": checked_map.topology.primary_valkey.static_ipv4,
        "restore_valkey": checked_map.topology.restore_valkey.static_ipv4,
    }
    expected_valkey_address = valkey_static_addresses.get(request.component)
    if (
        checked_policy.attach_protocol_v2_sha256 != protocol_sha
        or checked_policy.materialization_intent_sha256 != materialization_sha
        or checked_policy.wrapper_manifest_v2_sha256 != manifest_sha
        or checked_policy.v1_wrapper_manifest_sha256 != v1_wrapper_manifest_sha
        or checked_policy.v1_target_delivery_map_sha256 != map_sha
        or checked_policy.v1_attach_protocol_sha256 != v1_attach_protocol_sha
        or checked_policy.docker_attach_control_policy_sha256
        != docker_container_attach_v2_control_policy_sha256(checked_docker_attach_policy)
        or checked_policy.source_commit != checked_materialization_intent.source_commit
        or checked_manifest.source_commit != checked_materialization_intent.source_commit
        or checked_docker_attach_policy.source_commit
        != checked_materialization_intent.source_commit
        or checked_v1_wrapper_manifest.source_commit != checked_materialization_intent.source_commit
        or checked_v1_target_delivery_map.source_commit
        != checked_materialization_intent.source_commit
        or checked_docker_attach_policy.executor_control_policy_sha256
        != checked_materialization_intent.evidence.executor_control_policy_sha256
        or checked_manifest.v1_wrapper_manifest_sha256 != v1_wrapper_manifest_sha
        or checked_manifest.v1_target_delivery_map_sha256 != map_sha
        or checked_manifest.v1_attach_protocol_sha256 != v1_attach_protocol_sha
        or checked_manifest.attach_protocol_v2_sha256 != protocol_sha
        or checked_v1_target_delivery_map.wrapper_manifest_sha256 != v1_wrapper_manifest_sha
        or checked_v1_target_delivery_map.attach_protocol_sha256 != v1_attach_protocol_sha
        or checked_v1_target_delivery_map.allocation_intent_sha256
        != checked_policy.allocation_intent_sha256
        or checked_v1_wrapper_manifest.allocation_intent_sha256
        != checked_policy.allocation_intent_sha256
        or checked_v1_wrapper_manifest.attach_protocol_sha256 != v1_attach_protocol_sha
        or checked_materialization_intent.materialization_operation_id != request.operation_id
        or checked_materialization_intent.operation_scope != request.operation_scope
        or checked_materialization_intent.allocation_operation_id != request.allocation_operation_id
        or checked_materialization_intent.allocation_intent_sha256
        != checked_policy.allocation_intent_sha256
        or checked_materialization_intent.allocation_effect_receipt_sha256
        != checked_policy.allocation_effect_receipt_sha256
        or checked_materialization_intent.observed_allocation_attestation_sha256
        != checked_policy.observed_allocation_attestation_sha256
        or checked_materialization_intent.observed_restore_database_attestation_sha256
        != checked_policy.observed_restore_database_attestation_sha256
        or checked_materialization_intent.wrapper_manifest_sha256 != v1_wrapper_manifest_sha
        or checked_materialization_intent.target_delivery_map_sha256 != map_sha
        or checked_materialization_intent.container_attach_protocol_sha256 != v1_attach_protocol_sha
        or checked_materialization_intent.evidence.wrapper_manifest_sha256
        != v1_wrapper_manifest_sha
        or checked_materialization_intent.evidence.target_delivery_map_sha256 != map_sha
        or checked_materialization_intent.evidence.container_attach_protocol_sha256
        != v1_attach_protocol_sha
        or request.attach_protocol_sha256 != protocol_sha
        or request.wrapper_manifest_sha256 != manifest_sha
        or request.wrapper_profile_sha256 != wrapper_profile_sha
        or request.wrapper_artifact_binding_sha256 != artifact.artifact_binding_sha256
        or request.derived_image_policy_sha256 != canonical_sha256(artifact.derived_image_policy)
        or request.target_delivery_map_sha256 != map_sha
        or request.fields != target_fields
        or len(request.fields) > checked_protocol.max_chunks_per_target
        or total_secret_bytes > checked_protocol.max_total_secret_bytes
        or any(
            field.encoded_byte_count > checked_protocol.max_chunk_bytes for field in request.fields
        )
        or target_derived_image_sha != request.derived_image_policy_sha256
        or target_wrapper_binding != artifact.v1_wrapper_artifact_binding_sha256
        or target_protocol_sha != checked_policy.v1_attach_protocol_sha256
        or not container_bootstrap_v2_inspection_matches(checked_inspection, checked_template)
        or checked_template.component != request.component
        or checked_inspection.container_id != request.container_id
        or checked_inspection.runtime_hostname != request.runtime_hostname
        or request.runtime_instance_binding_sha256
        != container_attach_runtime_instance_binding_sha256(
            container_id=request.container_id,
            runtime_hostname=request.runtime_hostname,
        )
        or artifact.component != request.component
        or checked_template.entrypoint != artifact.wrapper_argv_prefix
        or checked_template.command != artifact.base_entrypoint + artifact.base_command
        or checked_template.merged_argv_sha256 != artifact.merged_argv_sha256
        or checked_template.static_image_environment != artifact.static_environment
        or checked_template.child_environment_policy != artifact.child_environment_policy
        or checked_template.valkey_launch_policy != artifact.valkey_launch_policy
        or not _v2_artifact_matches_v1_predecessor(
            artifact=artifact,
            v1_artifact=v1_artifact,
            v1_template=v1_template,
        )
        or not _v2_template_matches_materialization_predecessor(
            template=checked_template,
            artifact=artifact,
            v1_template=v1_template,
            component_plan=component_plan,
        )
        or checked_template.network_name != expected_placement.network_name
        or checked_template.network_alias != expected_placement.alias
        or checked_template.static_ipv4 != expected_placement.static_ipv4
        or (
            expected_valkey_address is not None
            and (
                artifact.valkey_launch_policy is None
                or artifact.valkey_launch_policy.isolated_bind_address != expected_valkey_address
                or checked_template.static_ipv4 != expected_valkey_address
                or checked_inspection.static_ipv4 != expected_valkey_address
            )
        )
        or ticket.base_registry_index_digest_sha256
        != artifact.base_image_policy.registry_index_digest_sha256
        or ticket.base_linux_amd64_manifest_digest_sha256
        != artifact.base_image_policy.linux_amd64_manifest_digest_sha256
        or ticket.base_config_digest_sha256 != artifact.base_image_policy.config_digest_sha256
        or ticket.derived_registry_index_digest_sha256
        != artifact.derived_image_policy.registry_index_digest_sha256
        or ticket.derived_linux_amd64_manifest_digest_sha256
        != artifact.derived_image_policy.linux_amd64_manifest_digest_sha256
        or ticket.derived_config_digest_sha256 != artifact.derived_image_policy.config_digest_sha256
        or ticket.wrapper_profile_sha256 != wrapper_profile_sha
        or ticket.wrapper_manifest_sha256 != manifest_sha
        or ticket.wrapper_artifact_binding_sha256 != artifact.artifact_binding_sha256
        or ticket.target_delivery_map_sha256 != map_sha
        or ticket.protocol_sha256 != protocol_sha
        or ticket.request_sha256 != container_attach_v2_request_sha256(request)
        or ticket.component != request.component
        or ticket.container_id != request.container_id
        or ticket.runtime_hostname != request.runtime_hostname
        or ticket.operation_id != request.operation_id
        or ticket.operation_scope != request.operation_scope
        or ticket.allocation_operation_id != request.allocation_operation_id
    ):
        raise _fresh_error("authorization")
    return _VerifiedContainerAttachV2Authorization._issue(
        capability=_VERIFIED_AUTHORIZATION_CAPABILITY,
        policy=checked_policy,
        protocol=checked_protocol,
        wrapper_manifest=checked_manifest,
        target_delivery_map=checked_map,
        v1_wrapper_manifest=checked_v1_wrapper_manifest,
        v1_attach_protocol=checked_v1_attach_protocol,
        materialization_intent=checked_materialization_intent,
        docker_attach_policy=checked_docker_attach_policy,
        template=checked_template,
        inspection=checked_inspection,
        envelope=checked_envelope,
        policy_sha256=policy_sha,
    )


def _expected_claim(
    authorization: _VerifiedContainerAttachV2Authorization,
) -> ContainerAttachClaimV2:
    request = authorization.envelope.request
    return ContainerAttachClaimV2(
        schema_version="rsd.container-attach-claim.v2",
        request_sha256=container_attach_v2_request_sha256(request),
        ticket_sha256=container_attach_authorization_ticket_sha256(authorization.envelope.ticket),
        state="claimed_v2",
        chunk_count=len(request.fields),
        chunk_descriptors_sha256=container_attach_chunk_descriptors_sha256(request.fields),
        actual_write_half_close_required=True,
        one_attach_per_container_lifetime=True,
    )


def _validate_ready(
    ready: ContainerAttachReadyV2, *, authorization: _VerifiedContainerAttachV2Authorization
) -> None:
    request = authorization.envelope.request
    ticket = authorization.envelope.ticket
    if (
        ready.request_sha256 != container_attach_v2_request_sha256(request)
        or ready.ticket_sha256 != container_attach_authorization_ticket_sha256(ticket)
        or ready.component != request.component
        or ready.container_id != request.container_id
        or ready.runtime_hostname != request.runtime_hostname
        or ready.state != request.expected_ready_state
        or ready.wrapper_profile_sha256 != request.wrapper_profile_sha256
        or ready.wrapper_artifact_binding_sha256 != request.wrapper_artifact_binding_sha256
        or ready.attach_protocol_sha256 != request.attach_protocol_sha256
        or ready.fields_sha256 != container_attach_chunk_descriptors_sha256(request.fields)
    ):
        raise _fresh_error("ready")


def _validate_claim(
    claim: ContainerAttachClaimV2, *, authorization: _VerifiedContainerAttachV2Authorization
) -> None:
    if claim != _expected_claim(authorization):
        raise _fresh_error("claim")


def _validate_ack(
    ack: ContainerAttachTerminalAckV2, *, authorization: _VerifiedContainerAttachV2Authorization
) -> None:
    request = authorization.envelope.request
    expected_claim = _expected_claim(authorization)
    if (
        ack.request_sha256 != expected_claim.request_sha256
        or ack.ticket_sha256 != expected_claim.ticket_sha256
        or ack.state != request.expected_terminal_ack_state
        or ack.chunk_count != expected_claim.chunk_count
        or ack.chunk_descriptors_sha256 != expected_claim.chunk_descriptors_sha256
        or ack.input_eof_observed is not True
        or ack.child_handoff_complete is not True
        or ack.staging_buffers_zeroized is not True
        or ack.protocol_output_close_required is not True
        or ack.child_process_readiness_claimed is not False
        or ack.service_readiness_claimed is not False
        or ack.persistence_allowed is not False
        or ack.logging_allowed is not False
        or ack.receipt_contains_secret is not False
    ):
        raise _fresh_error("ack")


def _ticket_claim(
    authorization: _VerifiedContainerAttachV2Authorization, *, boundary: str
) -> ContainerAttachV2TicketClaimV1:
    request = authorization.envelope.request
    return ContainerAttachV2TicketClaimV1(
        boundary=boundary,
        ticket_sha256=container_attach_authorization_ticket_sha256(authorization.envelope.ticket),
        request_sha256=container_attach_v2_request_sha256(request),
        allocation_operation_id=request.allocation_operation_id,
        operation_id=request.operation_id,
        component=request.component,
        container_id=request.container_id,
        request_nonce_sha256=request.request_nonce_sha256,
        target_delivery_map_sha256=request.target_delivery_map_sha256,
    )


def _container_lifetime_claim(
    authorization: _VerifiedContainerAttachV2Authorization,
) -> ContainerAttachV2ContainerLifetimeClaimV1:
    """Render the independent one-attach key for the full container lifetime."""

    request = authorization.envelope.request
    return ContainerAttachV2ContainerLifetimeClaimV1(
        boundary="daemon_send_v2",
        allocation_operation_id=request.allocation_operation_id,
        operation_id=request.operation_id,
        component=request.component,
        container_id=request.container_id,
        one_attach_per_container_lifetime=True,
    )


def _claim_ticket(
    authority: ContainerAttachV2TicketAuthority,
    authorization: _VerifiedContainerAttachV2Authorization,
    *,
    deadline: ContainerAttachV2Deadline,
) -> ContainerAttachV2TicketClaimResult:
    result: ContainerAttachV2TicketClaimResult | None = None
    failed = False
    try:
        result = authority.claim_ticket_and_container_once(
            _ticket_claim(authorization, boundary="daemon_send_v2"),
            _container_lifetime_claim(authorization),
            deadline=deadline,
        )
    except Exception:
        failed = True
    if failed or type(result) is not ContainerAttachV2TicketClaimResult:
        raise _fresh_error("ticket_authority")
    return result


class ContainerAttachV2DaemonSession:
    """One exact-once sender state machine for a future Engine attach.

    It never offers retry/resume/adoption.  A durable ticket authority is
    consumed before the claim frame is emitted.  Any abnormal result after the
    attempt starts becomes terminal ambiguity, so a new start/container/ticket
    is required.
    """

    __slots__ = (
        "_absolute_deadline",
        "_authorization",
        "_guard",
        "_state",
        "_ticket_authority",
    )

    def __init__(
        self,
        *,
        authorization: _VerifiedContainerAttachV2Authorization,
        deadline_clock: ContainerAttachV2MonotonicClock,
        ticket_authority: ContainerAttachV2TicketAuthority,
    ) -> None:
        if type(authorization) is not _VerifiedContainerAttachV2Authorization:
            raise _fresh_error("authorization")
        _require_authorization_fresh(
            policy=authorization.policy,
            ticket=authorization.envelope.ticket,
            materialization_intent=authorization.materialization_intent,
            phase="ticket",
        )
        self._authorization = authorization
        self._guard = _MonotonicGuard(deadline_clock)
        self._absolute_deadline = _deadline(
            self._guard,
            authorization.protocol.absolute_timeout_seconds,
            phase="deadline",
        )
        self._ticket_authority = ticket_authority
        self._state = ContainerAttachV2SessionState.NEW

    def _phase_deadline(self, seconds: int, *, phase: str) -> ContainerAttachV2Deadline:
        return _phase_deadline(self._guard, self._absolute_deadline, seconds, phase=phase)

    @property
    def state(self) -> ContainerAttachV2SessionState:
        return self._state

    @property
    def expected_claim(self) -> ContainerAttachClaimV2:
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        return _expected_claim(self._authorization)

    def checkpoint(self, *, journal_sequence: int) -> ContainerAttachCheckpointV2:
        """Project the current public state for a future durable journal."""

        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        request = self._authorization.envelope.request
        mapping: dict[
            ContainerAttachV2SessionState,
            Literal[
                "ticket_verified_v2",
                "ready_v2",
                "claimed_v2",
                "write_closed_v2",
                "terminal_ack_v2",
                "attach_ambiguous_v2",
                "attach_rejected_v2",
            ],
        ] = {
            ContainerAttachV2SessionState.NEW: "ticket_verified_v2",
            ContainerAttachV2SessionState.TICKET_SENT: "ticket_verified_v2",
            ContainerAttachV2SessionState.READY_RECEIVED: "ready_v2",
            ContainerAttachV2SessionState.CLAIM_SENT: "claimed_v2",
            ContainerAttachV2SessionState.CLAIM_ATTEMPTED: "attach_ambiguous_v2",
            ContainerAttachV2SessionState.CHUNKS_SENT: "claimed_v2",
            ContainerAttachV2SessionState.WRITE_CLOSED: "write_closed_v2",
            ContainerAttachV2SessionState.TERMINAL_ACK_RECEIVED: "terminal_ack_v2",
            ContainerAttachV2SessionState.CLOSED: "terminal_ack_v2",
            ContainerAttachV2SessionState.REJECTED: "attach_rejected_v2",
            ContainerAttachV2SessionState.AMBIGUOUS: "attach_ambiguous_v2",
        }
        checkpoint_state = mapping[self._state]
        return ContainerAttachCheckpointV2(
            schema_version="rsd.container-attach-checkpoint.v2",
            checkpoint_state=checkpoint_state,
            request_sha256=container_attach_v2_request_sha256(request),
            ticket_sha256=container_attach_authorization_ticket_sha256(
                self._authorization.envelope.ticket
            ),
            allocation_operation_id=request.allocation_operation_id,
            operation_id=request.operation_id,
            component=request.component,
            container_id=request.container_id,
            request_nonce_sha256=request.request_nonce_sha256,
            journal_sequence=journal_sequence,
            terminal=self._state
            in {
                ContainerAttachV2SessionState.CLOSED,
                ContainerAttachV2SessionState.REJECTED,
                ContainerAttachV2SessionState.AMBIGUOUS,
            },
            secret_persistence_allowed=False,
            secret_logging_allowed=False,
        )

    def write_ticket_envelope(self, writer: ContainerAttachV2DeadlineWriter) -> None:
        if self._state is not ContainerAttachV2SessionState.NEW:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        deadline = self._phase_deadline(
            self._authorization.protocol.ready_timeout_seconds, phase="ticket_envelope"
        )
        failed = False
        try:
            _write_frame(
                writer,
                self._guard,
                deadline,
                protocol=self._authorization.protocol,
                frame_type=ContainerAttachV2FrameType.TICKET_ENVELOPE,
                payload=_canonical_metadata(self._authorization.envelope),
                secret=False,
            )
        except Exception:
            failed = True
        if failed:
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error("ticket_envelope")
        self._state = ContainerAttachV2SessionState.TICKET_SENT

    def read_ready(self, reader: ContainerAttachV2DeadlineReader) -> ContainerAttachReadyV2:
        if self._state is not ContainerAttachV2SessionState.TICKET_SENT:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        ready: ContainerAttachReadyV2 | None = None
        failed = False
        try:
            deadline = self._phase_deadline(
                self._authorization.protocol.ready_timeout_seconds, phase="ready"
            )
            ready = _read_metadata(
                reader,
                self._guard,
                deadline,
                protocol=self._authorization.protocol,
                frame_type=ContainerAttachV2FrameType.READY,
                model_type=ContainerAttachReadyV2,
                phase="ready",
            )
            _validate_ready(ready, authorization=self._authorization)
        except Exception:
            failed = True
        if failed or ready is None:
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error("ready")
        self._state = ContainerAttachV2SessionState.READY_RECEIVED
        return ready

    def write_claim(self, writer: ContainerAttachV2DeadlineWriter) -> ContainerAttachClaimV2:
        if self._state is not ContainerAttachV2SessionState.READY_RECEIVED:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        claim = _expected_claim(self._authorization)
        result: ContainerAttachV2TicketClaimResult | None = None
        failed = False
        try:
            deadline = self._phase_deadline(
                self._authorization.protocol.claim_timeout_seconds, phase="claim"
            )
            self._state = ContainerAttachV2SessionState.CLAIM_ATTEMPTED
            result = _claim_ticket(self._ticket_authority, self._authorization, deadline=deadline)
            if result is ContainerAttachV2TicketClaimResult.REPLAYED:
                self._state = ContainerAttachV2SessionState.REJECTED
                raise _fresh_error("replay")
            if result is not ContainerAttachV2TicketClaimResult.CLAIMED:
                raise _fresh_error("ticket_authority")
            _write_frame(
                writer,
                self._guard,
                deadline,
                protocol=self._authorization.protocol,
                frame_type=ContainerAttachV2FrameType.CLAIM,
                payload=_canonical_metadata(claim),
                secret=False,
            )
        except Exception:
            failed = True
        if self._state is ContainerAttachV2SessionState.REJECTED:
            raise _fresh_error("replay")
        if failed or result is not ContainerAttachV2TicketClaimResult.CLAIMED:
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error("claim")
        self._state = ContainerAttachV2SessionState.CLAIM_SENT
        return claim

    def write_secret_chunks(
        self, writer: ContainerAttachV2DeadlineWriter, chunks: tuple[bytearray, ...]
    ) -> None:
        """Stream already-claimed chunks and scrub every mutable input on every path."""

        if type(chunks) is not tuple:
            _zeroize_discoverable_buffers(chunks)
            raise _fresh_error("secret_chunks")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        buffers = chunks
        if self._state is not ContainerAttachV2SessionState.CLAIM_SENT:
            _zeroize_discoverable_buffers(buffers)
            raise _fresh_error("state")
        request = self._authorization.envelope.request
        failure_phase: str | None = None
        try:
            total_secret_bytes = sum(len(item) for item in buffers if type(item) is bytearray)
            if (
                len(buffers) != len(request.fields)
                or any(type(item) is not bytearray for item in buffers)
                or any(
                    len(item) != field.encoded_byte_count
                    for item, field in zip(buffers, request.fields, strict=True)
                )
                or total_secret_bytes > self._authorization.protocol.max_total_secret_bytes
            ):
                failure_phase = "secret_chunks"
            else:
                deadline = self._phase_deadline(
                    self._authorization.protocol.terminal_ack_timeout_seconds,
                    phase="secret_chunk",
                )
                for descriptor, buffer in zip(request.fields, buffers, strict=True):
                    _require_secret_delivery_grammar(
                        descriptor, buffer, authorization=self._authorization
                    )
                self._state = ContainerAttachV2SessionState.CHUNKS_SENT
                for descriptor, buffer in zip(request.fields, buffers, strict=True):
                    _write_secret_frame(
                        writer,
                        self._guard,
                        deadline,
                        protocol=self._authorization.protocol,
                        ordinal=descriptor.ordinal,
                        chunk=buffer,
                    )
        except Exception:
            if self._state is not ContainerAttachV2SessionState.REJECTED:
                failure_phase = "frame_write"
        finally:
            _zeroize_discoverable_buffers(buffers)
        if failure_phase is not None:
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error(failure_phase)

    def close_write(self, duplex: ContainerAttachV2Duplex) -> None:
        """Require a real underlying ``shutdown(SHUT_WR)`` before reading ACK."""

        if self._state is not ContainerAttachV2SessionState.CHUNKS_SENT:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        result: object = None
        failed = False
        try:
            deadline = self._phase_deadline(
                self._authorization.protocol.terminal_ack_timeout_seconds,
                phase="write_close",
            )
            _require_before(self._guard, deadline, phase="write_close")
            result = duplex.close_write(deadline=deadline)
            _require_before(self._guard, deadline, phase="write_close")
        except Exception:
            failed = True
        if (
            failed
            or type(result) is not ContainerAttachV2WriteCloseResult
            or result is not ContainerAttachV2WriteCloseResult.HALF_CLOSED
        ):
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error("write_close")
        self._state = ContainerAttachV2SessionState.WRITE_CLOSED

    def read_terminal_ack(
        self, reader: ContainerAttachV2DeadlineReader
    ) -> ContainerAttachTerminalAckV2:
        if self._state is not ContainerAttachV2SessionState.WRITE_CLOSED:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        ack: ContainerAttachTerminalAckV2 | None = None
        failed = False
        try:
            deadline = self._phase_deadline(
                self._authorization.protocol.terminal_ack_timeout_seconds,
                phase="ack",
            )
            ack = _read_metadata(
                reader,
                self._guard,
                deadline,
                protocol=self._authorization.protocol,
                frame_type=ContainerAttachV2FrameType.TERMINAL_ACK,
                model_type=ContainerAttachTerminalAckV2,
                phase="ack",
            )
            _validate_ack(ack, authorization=self._authorization)
        except Exception:
            failed = True
        if failed or ack is None:
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error("ack")
        self._state = ContainerAttachV2SessionState.TERMINAL_ACK_RECEIVED
        return ack

    def require_protocol_output_eof(self, reader: ContainerAttachV2DeadlineReader) -> None:
        """Require wrapper protocol stdout to close immediately after its ACK."""

        if self._state is not ContainerAttachV2SessionState.TERMINAL_ACK_RECEIVED:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        failed = False
        try:
            deadline = self._phase_deadline(
                self._authorization.protocol.terminal_ack_timeout_seconds,
                phase="eof",
            )
            _require_before(self._guard, deadline, phase="eof")
            trailing = reader.read(1, deadline=deadline)
            _require_before(self._guard, deadline, phase="eof")
            if type(trailing) is not bytes or trailing != b"":
                raise ValueError
        except Exception:
            failed = True
        if failed:
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error("eof")
        self._state = ContainerAttachV2SessionState.CLOSED

    def receipt(self) -> ContainerAttachReceiptV2:
        """Return value-free evidence only after ACK and output EOF both occurred."""

        if self._state is not ContainerAttachV2SessionState.CLOSED:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        request = self._authorization.envelope.request
        ticket = self._authorization.envelope.ticket
        claim = _expected_claim(self._authorization)
        ack = ContainerAttachTerminalAckV2(
            schema_version="rsd.container-attach-terminal-ack.v2",
            request_sha256=claim.request_sha256,
            ticket_sha256=claim.ticket_sha256,
            state="terminal_ack_v2",
            chunk_count=claim.chunk_count,
            chunk_descriptors_sha256=claim.chunk_descriptors_sha256,
            input_eof_observed=True,
            child_handoff_complete=True,
            staging_buffers_zeroized=True,
            protocol_output_close_required=True,
            child_process_readiness_claimed=False,
            service_readiness_claimed=False,
            persistence_allowed=False,
            logging_allowed=False,
            receipt_contains_secret=False,
        )
        return ContainerAttachReceiptV2(
            schema_version="rsd.container-attach-receipt.v2",
            request_sha256=claim.request_sha256,
            ticket_sha256=container_attach_authorization_ticket_sha256(ticket),
            component=request.component,
            container_id=request.container_id,
            runtime_hostname=request.runtime_hostname,
            ready_state="ready_v2",
            claim_state="claimed_v2",
            write_closed_state="write_closed_v2",
            chunk_count=claim.chunk_count,
            chunk_descriptors_sha256=claim.chunk_descriptors_sha256,
            terminal_ack_state="terminal_ack_v2",
            terminal_ack_sha256=container_attach_v2_ack_sha256(ack),
            input_eof_observed=True,
            protocol_output_eof_observed=True,
            chunks_zeroized=True,
            persistence_allowed=False,
            logging_allowed=False,
            receipt_contains_secret=False,
            child_process_readiness_claimed=False,
            service_readiness_claimed=False,
        )


class ContainerAttachV2WrapperSession:
    """Pure wrapper-side state machine used only by offline codec tests.

    Real wrapper bytes are intentionally outside this Python-only contract
    slice.  The object makes the one-attach/EOF/ack ordering testable without
    pretending to be a process implementation or a durable journal.
    """

    __slots__ = ("_absolute_deadline", "_authorization", "_guard", "_state")

    def __init__(
        self,
        *,
        authorization: _VerifiedContainerAttachV2Authorization,
        deadline_clock: ContainerAttachV2MonotonicClock,
    ) -> None:
        if type(authorization) is not _VerifiedContainerAttachV2Authorization:
            raise _fresh_error("authorization")
        _require_authorization_fresh(
            policy=authorization.policy,
            ticket=authorization.envelope.ticket,
            materialization_intent=authorization.materialization_intent,
            phase="ticket",
        )
        self._authorization = authorization
        self._guard = _MonotonicGuard(deadline_clock)
        self._absolute_deadline = _deadline(
            self._guard,
            authorization.protocol.absolute_timeout_seconds,
            phase="deadline",
        )
        self._state = ContainerAttachV2SessionState.NEW

    def _phase_deadline(self, seconds: int, *, phase: str) -> ContainerAttachV2Deadline:
        return _phase_deadline(self._guard, self._absolute_deadline, seconds, phase=phase)

    @property
    def state(self) -> ContainerAttachV2SessionState:
        return self._state

    def write_ready(self, writer: ContainerAttachV2DeadlineWriter) -> ContainerAttachReadyV2:
        if self._state is not ContainerAttachV2SessionState.NEW:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        request = self._authorization.envelope.request
        ready = ContainerAttachReadyV2(
            schema_version="rsd.container-attach-ready.v2",
            request_sha256=container_attach_v2_request_sha256(request),
            ticket_sha256=container_attach_authorization_ticket_sha256(
                self._authorization.envelope.ticket
            ),
            component=request.component,
            container_id=request.container_id,
            runtime_hostname=request.runtime_hostname,
            state="ready_v2",
            wrapper_profile_sha256=request.wrapper_profile_sha256,
            wrapper_artifact_binding_sha256=request.wrapper_artifact_binding_sha256,
            attach_protocol_sha256=request.attach_protocol_sha256,
            fields_sha256=container_attach_chunk_descriptors_sha256(request.fields),
        )
        failed = False
        try:
            deadline = self._phase_deadline(
                self._authorization.protocol.ready_timeout_seconds, phase="ready"
            )
            _write_frame(
                writer,
                self._guard,
                deadline,
                protocol=self._authorization.protocol,
                frame_type=ContainerAttachV2FrameType.READY,
                payload=_canonical_metadata(ready),
                secret=False,
            )
        except Exception:
            failed = True
        if failed:
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error("ready")
        self._state = ContainerAttachV2SessionState.READY_RECEIVED
        return ready

    def read_claim(self, reader: ContainerAttachV2DeadlineReader) -> ContainerAttachClaimV2:
        if self._state is not ContainerAttachV2SessionState.READY_RECEIVED:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        claim: ContainerAttachClaimV2 | None = None
        failed = False
        try:
            deadline = self._phase_deadline(
                self._authorization.protocol.claim_timeout_seconds, phase="claim"
            )
            claim = _read_metadata(
                reader,
                self._guard,
                deadline,
                protocol=self._authorization.protocol,
                frame_type=ContainerAttachV2FrameType.CLAIM,
                model_type=ContainerAttachClaimV2,
                phase="claim",
            )
            _validate_claim(claim, authorization=self._authorization)
        except Exception:
            failed = True
        if failed or claim is None:
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error("claim")
        self._state = ContainerAttachV2SessionState.CLAIM_SENT
        return claim

    def consume_secret_chunks(
        self, reader: ContainerAttachV2DeadlineReader, sink: ContainerAttachV2SecretSink
    ) -> None:
        if self._state is not ContainerAttachV2SessionState.CLAIM_SENT:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        request = self._authorization.envelope.request
        failure_phase: str | None = None
        consumed_secret_bytes = 0
        for descriptor in request.fields:
            buffer: bytearray | None = None
            try:
                deadline = self._phase_deadline(
                    self._authorization.protocol.terminal_ack_timeout_seconds,
                    phase="secret_chunk",
                )
                buffer = _read_secret_chunk(
                    reader,
                    self._guard,
                    deadline,
                    protocol=self._authorization.protocol,
                    expected_ordinal=descriptor.ordinal,
                )
                if len(buffer) != descriptor.encoded_byte_count:
                    raise ValueError
                consumed_secret_bytes += len(buffer)
                if consumed_secret_bytes > self._authorization.protocol.max_total_secret_bytes:
                    raise ValueError
                _require_secret_delivery_grammar(
                    descriptor, buffer, authorization=self._authorization
                )
                sink.accept(descriptor, memoryview(buffer))
            except Exception:
                failure_phase = "target_sink" if buffer is not None else "secret_chunk"
            finally:
                if buffer is not None:
                    _zeroize(buffer)
            if failure_phase is not None:
                break
        if failure_phase is not None:
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error(failure_phase)
        self._state = ContainerAttachV2SessionState.CHUNKS_SENT

    def require_input_eof(self, reader: ContainerAttachV2DeadlineReader) -> None:
        if self._state is not ContainerAttachV2SessionState.CHUNKS_SENT:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        failed = False
        try:
            deadline = self._phase_deadline(
                self._authorization.protocol.terminal_ack_timeout_seconds, phase="eof"
            )
            _require_before(self._guard, deadline, phase="eof")
            trailing = reader.read(1, deadline=deadline)
            _require_before(self._guard, deadline, phase="eof")
            if type(trailing) is not bytes or trailing != b"":
                raise ValueError
        except Exception:
            failed = True
        if failed:
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error("eof")
        self._state = ContainerAttachV2SessionState.WRITE_CLOSED

    def write_terminal_ack_and_close_output(
        self,
        writer: ContainerAttachV2DeadlineWriter,
        closer: ContainerAttachV2OutputCloser,
    ) -> ContainerAttachTerminalAckV2:
        if self._state is not ContainerAttachV2SessionState.WRITE_CLOSED:
            raise _fresh_error("state")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        claim = _expected_claim(self._authorization)
        ack = ContainerAttachTerminalAckV2(
            schema_version="rsd.container-attach-terminal-ack.v2",
            request_sha256=claim.request_sha256,
            ticket_sha256=claim.ticket_sha256,
            state="terminal_ack_v2",
            chunk_count=claim.chunk_count,
            chunk_descriptors_sha256=claim.chunk_descriptors_sha256,
            input_eof_observed=True,
            child_handoff_complete=True,
            staging_buffers_zeroized=True,
            protocol_output_close_required=True,
            child_process_readiness_claimed=False,
            service_readiness_claimed=False,
            persistence_allowed=False,
            logging_allowed=False,
            receipt_contains_secret=False,
        )
        failed = False
        try:
            deadline = self._phase_deadline(
                self._authorization.protocol.terminal_ack_timeout_seconds, phase="ack"
            )
            _write_frame(
                writer,
                self._guard,
                deadline,
                protocol=self._authorization.protocol,
                frame_type=ContainerAttachV2FrameType.TERMINAL_ACK,
                payload=_canonical_metadata(ack),
                secret=False,
            )
            _require_before(self._guard, deadline, phase="ack")
            result = closer.close_output(deadline=deadline)
            _require_before(self._guard, deadline, phase="ack")
            if (
                type(result) is not ContainerAttachV2OutputCloseResult
                or result is not ContainerAttachV2OutputCloseResult.OUTPUT_CLOSED
            ):
                raise ValueError
        except Exception:
            failed = True
        if failed:
            self._state = ContainerAttachV2SessionState.AMBIGUOUS
            raise _fresh_error("ack")
        self._state = ContainerAttachV2SessionState.CLOSED
        return ack


def read_container_attach_v2_ticket_envelope(
    reader: ContainerAttachV2DeadlineReader,
    *,
    protocol: ContainerBootstrapAttachProtocolV2,
    policy: ContainerAttachV2AuthorizationPolicyV1,
    wrapper_manifest: ContainerBootstrapWrapperManifestV2,
    target_delivery_map: TargetDeliveryMapV1,
    v1_wrapper_manifest: ContainerBootstrapWrapperManifestV1,
    v1_attach_protocol: ContainerBootstrapAttachProtocolV1,
    materialization_intent: MaterializationIntentV1,
    docker_attach_policy: DockerContainerAttachControlPolicyV2,
    template: ContainerBootstrapTemplateV2,
    inspection: ContainerBootstrapInspectionV2,
    trust_anchor: ContainerAttachTicketTrustAnchorV1,
    deadline_clock: ContainerAttachV2MonotonicClock,
) -> _VerifiedContainerAttachV2Authorization:
    """Read the mandatory first ticket frame and verify all V2 authority.

    No ready acknowledgement is produced until this function succeeds, so a
    malformed, stale, wrong-hostname, wrong-image, or unsigned ticket cannot
    become a secret-delivery path.
    """

    checked_protocol = _strict_model(
        protocol, ContainerBootstrapAttachProtocolV2, phase="attach_protocol"
    )
    guard = _MonotonicGuard(deadline_clock)
    absolute_deadline = _deadline(
        guard, checked_protocol.absolute_timeout_seconds, phase="ticket_envelope"
    )
    deadline = _phase_deadline(
        guard,
        absolute_deadline,
        checked_protocol.ready_timeout_seconds,
        phase="ticket_envelope",
    )
    envelope = _read_metadata(
        reader,
        guard,
        deadline,
        protocol=checked_protocol,
        frame_type=ContainerAttachV2FrameType.TICKET_ENVELOPE,
        model_type=ContainerAttachTicketEnvelopeV2,
        phase="ticket_envelope",
    )
    return verify_container_attach_v2_authorization(
        policy=policy,
        protocol=checked_protocol,
        wrapper_manifest=wrapper_manifest,
        target_delivery_map=target_delivery_map,
        v1_wrapper_manifest=v1_wrapper_manifest,
        v1_attach_protocol=v1_attach_protocol,
        materialization_intent=materialization_intent,
        docker_attach_policy=docker_attach_policy,
        template=template,
        inspection=inspection,
        envelope=envelope,
        trust_anchor=trust_anchor,
    )


class _RawSocket(Protocol):
    def send(self, data: bytes | memoryview) -> int: ...

    def recv(self, count: int) -> bytes: ...

    def settimeout(self, value: float | None) -> object: ...

    def shutdown(self, how: int) -> object: ...

    def close(self) -> object: ...


def _attach_request_bytes(policy: DockerContainerAttachControlPolicyV2, container_id: str) -> bytes:
    if (
        type(container_id) is not str
        or len(container_id) != 64
        or any(character not in "0123456789abcdef" for character in container_id)
    ):
        raise _fresh_error("attach_endpoint")
    target = (
        f"/v{policy.api_version}/containers/{container_id}/attach?"
        "stdin=1&stdout=1&stderr=1&stream=1&logs=0"
    )
    request = (
        f"POST {target} HTTP/1.1\r\n"
        "Host: docker\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: tcp\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode("ascii")
    if len(request) > policy.max_request_bytes:
        raise _fresh_error("attach_endpoint")
    return request


class _RawUnixDockerAttachV2ForTest:
    """Pure-fake non-TTY mux codec, deliberately unavailable to production.

    It sends the one exact upgrade request, demultiplexes only stdout frames,
    rejects stderr/unknown streams, and exposes a true socket ``SHUT_WR``.
    A pathname connector is intentionally absent: a pre-connect ``lstat``
    cannot pin the peer selected by a later AF_UNIX ``connect``.  Until a
    separately reviewed descriptor-bound installation adapter exists, this
    class stays module-internal and omitted from every public export.  Its
    fake-only constructor accepts an already supplied test stream; it never
    opens or connects an AF_UNIX pathname.  That leaves no production
    path-based socket operation in this contract-only slice.
    """

    __slots__ = (
        "_absolute_deadline",
        "_application_buffer",
        "_authorization",
        "_closed_write",
        "_guard",
        "_mux_buffer",
        "_mux_frames",
        "_policy",
        "_protocol",
        "_socket",
        "_stdout_bytes",
    )

    def __init__(
        self,
        *,
        raw_socket: _RawSocket,
        authorization: _VerifiedContainerAttachV2Authorization,
        guard: _MonotonicGuard,
        absolute_deadline: ContainerAttachV2Deadline,
        initial: bytes = b"",
    ) -> None:
        if type(authorization) is not _VerifiedContainerAttachV2Authorization:
            raise _fresh_error("authorization")
        _require_authorization_fresh(
            policy=authorization.policy,
            ticket=authorization.envelope.ticket,
            materialization_intent=authorization.materialization_intent,
            phase="ticket",
        )
        self._socket = raw_socket
        self._authorization = authorization
        self._policy = authorization.docker_attach_policy
        self._protocol = authorization.protocol
        if (
            self._protocol.max_stdout_bytes > self._policy.max_stdout_bytes
            or self._protocol.max_stdout_frames > self._policy.max_stdout_frames
            or self._protocol.absolute_timeout_seconds > self._policy.absolute_timeout_seconds
        ):
            raise _fresh_error("attach_policy")
        _require_before(guard, absolute_deadline, phase="attach_policy")
        self._guard = guard
        self._absolute_deadline = absolute_deadline
        self._mux_buffer = bytearray(initial)
        self._application_buffer = bytearray()
        self._closed_write = False
        self._mux_frames = 0
        self._stdout_bytes = 0

    @classmethod
    def _from_fake_socket_for_test(
        cls,
        *,
        raw_socket: _RawSocket,
        authorization: _VerifiedContainerAttachV2Authorization,
        deadline_clock: ContainerAttachV2MonotonicClock,
    ) -> _RawUnixDockerAttachV2ForTest:
        """Pure fake-only upgrade seam; it never opens a socket itself."""

        if type(authorization) is not _VerifiedContainerAttachV2Authorization:
            raise _fresh_error("authorization")
        _require_authorization_fresh(
            policy=authorization.policy,
            ticket=authorization.envelope.ticket,
            materialization_intent=authorization.materialization_intent,
            phase="ticket",
        )
        checked_policy = authorization.docker_attach_policy
        checked_protocol = authorization.protocol
        if checked_protocol.absolute_timeout_seconds > checked_policy.absolute_timeout_seconds:
            raise _fresh_error("attach_policy")
        guard = _MonotonicGuard(deadline_clock)
        absolute_deadline = _deadline(
            guard, checked_policy.absolute_timeout_seconds, phase="attach_handshake"
        )
        return cls._upgrade(
            raw_socket=raw_socket,
            authorization=authorization,
            guard=guard,
            absolute_deadline=absolute_deadline,
        )

    @classmethod
    def _upgrade(
        cls,
        *,
        raw_socket: _RawSocket,
        authorization: _VerifiedContainerAttachV2Authorization,
        guard: _MonotonicGuard,
        absolute_deadline: ContainerAttachV2Deadline,
    ) -> _RawUnixDockerAttachV2ForTest:
        if type(authorization) is not _VerifiedContainerAttachV2Authorization:
            raise _fresh_error("authorization")
        _require_authorization_fresh(
            policy=authorization.policy,
            ticket=authorization.envelope.ticket,
            materialization_intent=authorization.materialization_intent,
            phase="ticket",
        )
        checked_policy = authorization.docker_attach_policy
        deadline = _phase_deadline(
            guard,
            absolute_deadline,
            checked_policy.request_timeout_seconds,
            phase="attach_handshake",
        )
        request = _attach_request_bytes(checked_policy, authorization.envelope.request.container_id)
        result: _RawUnixDockerAttachV2ForTest | None = None
        failed = False
        try:
            cls._socket_write_exact(raw_socket, request, guard=guard, deadline=deadline)
            header, remaining = cls._read_http_upgrade(
                raw_socket,
                policy=checked_policy,
                guard=guard,
                deadline=deadline,
            )
            cls._validate_http_upgrade(header)
            result = cls(
                raw_socket=raw_socket,
                authorization=authorization,
                guard=guard,
                absolute_deadline=absolute_deadline,
                initial=remaining,
            )
        except Exception:
            failed = True
        if failed or result is None:
            with suppress(Exception):
                raw_socket.close()
            raise _fresh_error("attach_handshake")
        return result

    @staticmethod
    def _socket_write_exact(
        raw_socket: _RawSocket,
        data: bytes,
        *,
        guard: _MonotonicGuard,
        deadline: ContainerAttachV2Deadline,
    ) -> None:
        offset = 0
        failed = False
        try:
            while offset < len(data):
                _require_before(guard, deadline, phase="attach_handshake")
                raw_socket.settimeout(deadline.remaining_seconds())
                written = raw_socket.send(memoryview(data)[offset:])
                _require_before(guard, deadline, phase="attach_handshake")
                if type(written) is not int or written < 1 or written > len(data) - offset:
                    raise ValueError
                offset += written
        except Exception:
            failed = True
        if failed:
            raise _fresh_error("attach_handshake")

    @staticmethod
    def _read_http_upgrade(
        raw_socket: _RawSocket,
        *,
        policy: DockerContainerAttachControlPolicyV2,
        guard: _MonotonicGuard,
        deadline: ContainerAttachV2Deadline,
    ) -> tuple[bytes, bytes]:
        data = bytearray()
        failed = False
        try:
            while b"\r\n\r\n" not in data:
                _require_before(guard, deadline, phase="attach_handshake")
                raw_socket.settimeout(deadline.remaining_seconds())
                block = raw_socket.recv(min(4096, policy.max_response_header_bytes - len(data)))
                _require_before(guard, deadline, phase="attach_handshake")
                if type(block) is not bytes or not block:
                    raise ValueError
                data.extend(block)
                if len(data) > policy.max_response_header_bytes:
                    raise ValueError
            marker = data.index(b"\r\n\r\n") + 4
            header = bytes(data[:marker])
            remaining = bytes(data[marker:])
        except Exception:
            failed = True
            header = b""
            remaining = b""
        finally:
            _zeroize(data)
        if failed:
            raise _fresh_error("attach_handshake")
        return header, remaining

    @staticmethod
    def _validate_http_upgrade(header: bytes) -> None:
        failed = False
        try:
            lines = header.decode("ascii").split("\r\n")
            if lines[0] != "HTTP/1.1 101 UPGRADED" or lines[-2:] != ["", ""]:
                raise ValueError
            pairs = [line.split(":", 1) for line in lines[1:-2]]
            if any(len(pair) != 2 for pair in pairs):
                raise ValueError
            normalized_pairs = [
                (name.lower().strip(), value.strip().lower()) for name, value in pairs
            ]
            if len({name for name, _ in normalized_pairs}) != len(normalized_pairs):
                raise ValueError
            normalized = dict(normalized_pairs)
            if normalized.get("connection") != "upgrade" or normalized.get("upgrade") != "tcp":
                raise ValueError
            if "content-length" in normalized or "transfer-encoding" in normalized:
                raise ValueError
        except Exception:
            failed = True
        if failed:
            raise _fresh_error("attach_handshake")

    def _socket_timeout(self, deadline: ContainerAttachV2Deadline, *, phase: str) -> float:
        """Intersect the caller phase deadline with this attach's absolute deadline."""

        remaining = 0.0
        failed = False
        try:
            _require_before(self._guard, self._absolute_deadline, phase=phase)
            if type(deadline) is not ContainerAttachV2Deadline or not deadline._issued_by(
                self._guard
            ):
                raise ValueError
            remaining = min(
                self._absolute_deadline.remaining_seconds(),
                deadline.remaining_seconds(),
                float(self._policy.idle_timeout_seconds),
            )
            if not _valid_monotonic(remaining) or remaining <= 0.0:
                raise ValueError
        except Exception:
            failed = True
        if failed:
            raise _fresh_error(phase)
        return remaining

    def _recv_exact(self, count: int, *, deadline: ContainerAttachV2Deadline) -> bytes:
        result = bytearray()
        failed = False
        try:
            while len(result) < count:
                self._socket.settimeout(self._socket_timeout(deadline, phase="frame_payload"))
                block = self._socket.recv(count - len(result))
                if type(block) is not bytes or not block or len(block) > count - len(result):
                    raise ValueError
                result.extend(block)
        except Exception:
            failed = True
        if failed:
            _zeroize(result)
            raise _fresh_error("frame_payload")
        rendered = bytes(result)
        _zeroize(result)
        return rendered

    def _next_stdout_frame(self, *, deadline: ContainerAttachV2Deadline) -> bytes | None:
        failed = False
        try:
            while len(self._mux_buffer) < _DOCKER_MUX_HEADER_BYTES:
                self._socket.settimeout(self._socket_timeout(deadline, phase="frame_payload"))
                block = self._socket.recv(_DOCKER_MUX_HEADER_BYTES - len(self._mux_buffer))
                if type(block) is not bytes:
                    raise ValueError
                if block == b"":
                    if self._mux_buffer == bytearray():
                        return None
                    raise ValueError
                self._mux_buffer.extend(block)
        except Exception:
            failed = True
        if failed:
            raise _fresh_error("frame_payload")
        header = bytes(self._mux_buffer[:_DOCKER_MUX_HEADER_BYTES])
        del self._mux_buffer[:_DOCKER_MUX_HEADER_BYTES]
        payload: bytes | None = None
        failed = False
        try:
            stream, length = _DOCKER_MUX_HEADER.unpack(header)
            self._mux_frames += 1
            if (
                self._mux_frames > self._policy.max_stdout_frames
                or stream != 1
                or length == 0
                or length > self._policy.max_stdout_bytes - self._stdout_bytes
            ):
                raise ValueError
            while len(self._mux_buffer) < length:
                self._mux_buffer.extend(
                    self._recv_exact(length - len(self._mux_buffer), deadline=deadline)
                )
            payload = bytes(self._mux_buffer[:length])
            del self._mux_buffer[:length]
            self._stdout_bytes += length
        except Exception:
            failed = True
        if failed or payload is None:
            raise _fresh_error("frame_payload")
        return payload

    def read(self, count: int, *, deadline: ContainerAttachV2Deadline) -> bytes:
        if type(count) is not int or count < 0:
            raise _fresh_error("frame_payload")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        self._socket_timeout(deadline, phase="frame_payload")
        if count == 0:
            return b""
        if self._application_buffer:
            value = bytes(self._application_buffer[:count])
            del self._application_buffer[: len(value)]
            return value
        payload = self._next_stdout_frame(deadline=deadline)
        if payload is None:
            return b""
        self._application_buffer.extend(payload)
        value = bytes(self._application_buffer[:count])
        del self._application_buffer[: len(value)]
        return value

    def write(
        self, data: bytes | bytearray | memoryview, *, deadline: ContainerAttachV2Deadline
    ) -> int:
        if self._closed_write:
            raise _fresh_error("frame_write")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        rendered = memoryview(data)
        written: object = None
        failed = False
        try:
            self._socket.settimeout(self._socket_timeout(deadline, phase="frame_write"))
            written = self._socket.send(rendered)
            if type(written) is not int or written < 0 or written > len(rendered):
                raise ValueError
        except Exception:
            failed = True
        if failed or type(written) is not int:
            raise _fresh_error("frame_write")
        return written

    def close_write(
        self, *, deadline: ContainerAttachV2Deadline
    ) -> ContainerAttachV2WriteCloseResult:
        if self._closed_write:
            raise _fresh_error("write_close")
        _require_authorization_fresh(
            policy=self._authorization.policy,
            ticket=self._authorization.envelope.ticket,
            materialization_intent=self._authorization.materialization_intent,
            phase="ticket",
        )
        failed = False
        try:
            self._socket.settimeout(self._socket_timeout(deadline, phase="write_close"))
            self._socket.shutdown(socket.SHUT_WR)
        except Exception:
            failed = True
        if failed:
            raise _fresh_error("write_close")
        self._closed_write = True
        return ContainerAttachV2WriteCloseResult.HALF_CLOSED

    def close(self) -> None:
        _zeroize(self._mux_buffer)
        _zeroize(self._application_buffer)
        with suppress(Exception):
            self._socket.close()


__all__ = [
    "ContainerAttachV2ContainerLifetimeClaimV1",
    "ContainerAttachV2DaemonSession",
    "ContainerAttachV2Deadline",
    "ContainerAttachV2DeadlineReader",
    "ContainerAttachV2DeadlineWriter",
    "ContainerAttachV2Duplex",
    "ContainerAttachV2Error",
    "ContainerAttachV2FrameType",
    "ContainerAttachV2MonotonicClock",
    "ContainerAttachV2OutputCloseResult",
    "ContainerAttachV2OutputCloser",
    "ContainerAttachV2SecretSink",
    "ContainerAttachV2SessionState",
    "ContainerAttachV2TicketAuthority",
    "ContainerAttachV2TicketClaimResult",
    "ContainerAttachV2TicketClaimV1",
    "ContainerAttachV2WrapperSession",
    "ContainerAttachV2WriteCloseResult",
    "read_container_attach_v2_ticket_envelope",
    "verify_container_attach_v2_authorization",
]
