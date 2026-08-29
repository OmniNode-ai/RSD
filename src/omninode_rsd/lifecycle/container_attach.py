"""Bounded local daemon-to-container bootstrap attach framing.

This module is deliberately separate from the Mac-to-daemon remote-session transport.
It supplies only a value-redacted binary framing contract for a future direct
container-stdin adapter.  It neither creates a container nor opens an attach
connection, reads a provider, renders a URI, or starts a workload.

The only secret-bearing interface is ``write_secret_chunks`` /
``read_secret_chunks``.  It accepts mutable buffers, sends or consumes them in
the exact signed field order, and best-effort zeroizes every buffer on every
exit path.  The receipt-safe models and all errors contain metadata only.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Final, Protocol, cast

from pydantic import BaseModel, ValidationError

from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerAttachClaimV1,
    ContainerAttachReadyV1,
    ContainerAttachRequestV1,
    ContainerAttachTerminalAckV1,
    ContainerBootstrapAttachProtocolV1,
    TargetDeliveryFieldV1,
    container_attach_chunk_descriptors_sha256,
    container_attach_request_sha256,
    container_bootstrap_attach_protocol_sha256,
)

_MAGIC: Final = b"ONCA"
_FRAME_VERSION: Final = 1
_HEADER: Final = struct.Struct("!4sBBI")
_HEADER_BYTES: Final = _HEADER.size
_CHUNK_ORDINAL: Final = struct.Struct("!H")


class ContainerAttachError(RuntimeError):
    """Value-redacted failure at the future local-container boundary."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__(f"container attach failed at phase: {phase}")


class ContainerAttachFrameType(IntEnum):
    """The one fixed directional frame set for local wrapper bootstrap."""

    REQUEST = 1
    READY = 2
    CLAIM = 3
    SECRET_CHUNK = 4
    TERMINAL_ACK = 5


class ContainerAttachSessionState(StrEnum):
    """Monotonic local delivery states; ambiguity is terminal."""

    NEW = "new"
    REQUEST_SENT = "request_sent"
    READY_RECEIVED = "ready_received"
    CLAIM_SENT = "claim_sent"
    CHUNKS_SENT = "chunks_sent"
    TERMINAL_ACK_RECEIVED = "terminal_ack_received"
    CLOSED = "closed"
    AMBIGUOUS = "ambiguous"


class AttachByteReader(Protocol):
    """Narrow binary reader required by the pure framing codec."""

    def read(self, count: int) -> bytes: ...


class AttachByteWriter(Protocol):
    """Narrow binary writer required by the pure framing codec."""

    def write(self, data: bytes | bytearray | memoryview) -> object: ...


class ContainerAttachSecretSink(Protocol):
    """The sole target-side capability that may observe a chunk briefly."""

    def accept(self, descriptor: TargetDeliveryFieldV1, value: memoryview) -> None: ...


def _zeroize(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _canonical_metadata(model: BaseModel) -> bytes:
    try:
        return json.dumps(
            model.model_dump(mode="json", warnings="error"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError):
        raise ContainerAttachError("metadata") from None


def _same_exact_shape(original: object, canonical: object) -> bool:
    """Reject raw-string enum and nested ``model_construct`` type drift."""

    if type(original) is not type(canonical):
        return False
    if isinstance(original, BaseModel):
        if not isinstance(canonical, BaseModel):
            return False
        return all(
            _same_exact_shape(getattr(original, name), getattr(canonical, name))
            for name in original.__class__.model_fields
        )
    if type(original) is tuple:
        canonical_tuple = cast(tuple[object, ...], canonical)
        return len(original) == len(canonical_tuple) and all(
            _same_exact_shape(left, item)
            for left, item in zip(original, canonical_tuple, strict=True)
        )
    if type(original) is list:
        canonical_list = cast(list[object], canonical)
        return len(original) == len(canonical_list) and all(
            _same_exact_shape(left, item)
            for left, item in zip(original, canonical_list, strict=True)
        )
    if type(original) is dict:
        canonical_dict = cast(dict[object, object], canonical)
        return len(original) == len(canonical_dict) and all(
            _same_exact_shape(left_key, right_key)
            and _same_exact_shape(original[left_key], canonical_dict[right_key])
            for left_key, right_key in zip(original, canonical_dict, strict=True)
        )
    return original == canonical


def _strict_model[ModelType: BaseModel](
    value: object, model_type: type[ModelType], *, phase: str
) -> ModelType:
    if type(value) is not model_type:
        raise ContainerAttachError(phase)
    try:
        original = _canonical_metadata(cast(BaseModel, value))
        canonical = model_type.model_validate_json(original, strict=True)
        rendered = _canonical_metadata(canonical)
    except (ContainerAttachError, TypeError, ValidationError, ValueError):
        raise ContainerAttachError(phase) from None
    if (
        type(canonical) is not model_type
        or original != rendered
        or not _same_exact_shape(value, canonical)
    ):
        raise ContainerAttachError(phase)
    return canonical


def _read_exact(
    reader: AttachByteReader, count: int, *, mutable: bool, phase: str
) -> bytes | bytearray:
    if type(count) is not int or count < 0:
        raise ContainerAttachError(phase)
    result = bytearray()
    failed = False
    try:
        while len(result) < count:
            block = reader.read(count - len(result))
            if type(block) is not bytes or not block or len(block) > count - len(result):
                raise ContainerAttachError(phase)
            result.extend(block)
    except ContainerAttachError:
        failed = True
    except Exception:
        failed = True
    if failed:
        _zeroize(result)
        raise ContainerAttachError(phase)
    if mutable:
        return result
    rendered = bytes(result)
    _zeroize(result)
    return rendered


def _write(writer: AttachByteWriter, data: bytes | bytearray | memoryview, *, phase: str) -> None:
    failed = False
    try:
        written = writer.write(data)
    except Exception:
        failed = True
        written = None
    if failed or (written is not None and (type(written) is not int or written != len(data))):
        raise ContainerAttachError(phase)


def _write_frame(
    writer: AttachByteWriter,
    *,
    protocol: ContainerBootstrapAttachProtocolV1,
    frame_type: ContainerAttachFrameType,
    payload: bytes | bytearray | memoryview,
    secret: bool,
) -> None:
    limit = (
        protocol.max_chunk_bytes + _CHUNK_ORDINAL.size if secret else protocol.max_metadata_bytes
    )
    if len(payload) > limit:
        raise ContainerAttachError("frame_size")
    header = _HEADER.pack(_MAGIC, _FRAME_VERSION, int(frame_type), len(payload))
    _write(writer, header, phase="frame_write")
    _write(writer, payload, phase="frame_write")


def _read_frame(
    reader: AttachByteReader,
    *,
    protocol: ContainerBootstrapAttachProtocolV1,
    expected_type: ContainerAttachFrameType,
    secret: bool,
) -> bytes | bytearray:
    header = _read_exact(reader, _HEADER_BYTES, mutable=False, phase="frame_header")
    try:
        magic, version, raw_type, length = _HEADER.unpack(cast(bytes, header))
        frame_type = ContainerAttachFrameType(raw_type)
    except (ValueError, struct.error):
        raise ContainerAttachError("frame_header") from None
    if (
        magic != _MAGIC
        or version != _FRAME_VERSION
        or frame_type is not expected_type
        or length
        > (
            protocol.max_chunk_bytes + _CHUNK_ORDINAL.size
            if secret
            else protocol.max_metadata_bytes
        )
    ):
        raise ContainerAttachError("frame_header")
    return _read_exact(reader, length, mutable=secret, phase="frame_payload")


def _read_metadata[ModelType: BaseModel](
    reader: AttachByteReader,
    *,
    protocol: ContainerBootstrapAttachProtocolV1,
    frame_type: ContainerAttachFrameType,
    model_type: type[ModelType],
    phase: str,
) -> ModelType:
    raw = _read_frame(reader, protocol=protocol, expected_type=frame_type, secret=False)
    try:
        model = model_type.model_validate_json(cast(bytes, raw), strict=True)
        if _canonical_metadata(model) != raw:
            raise ContainerAttachError(phase)
    except (ContainerAttachError, TypeError, ValidationError, ValueError):
        raise ContainerAttachError(phase) from None
    return _strict_model(model, model_type, phase=phase)


def _write_secret_frame(
    writer: AttachByteWriter,
    *,
    protocol: ContainerBootstrapAttachProtocolV1,
    ordinal: int,
    chunk: bytearray,
) -> None:
    if not 1 <= ordinal <= protocol.max_chunks_per_target or len(chunk) > protocol.max_chunk_bytes:
        raise ContainerAttachError("secret_chunk")
    header = _HEADER.pack(
        _MAGIC,
        _FRAME_VERSION,
        int(ContainerAttachFrameType.SECRET_CHUNK),
        _CHUNK_ORDINAL.size + len(chunk),
    )
    _write(writer, header, phase="frame_write")
    _write(writer, _CHUNK_ORDINAL.pack(ordinal), phase="frame_write")
    _write(writer, memoryview(chunk), phase="frame_write")


def _read_secret_chunk(
    reader: AttachByteReader,
    *,
    protocol: ContainerBootstrapAttachProtocolV1,
    expected_ordinal: int,
) -> bytearray:
    payload = _read_frame(
        reader,
        protocol=protocol,
        expected_type=ContainerAttachFrameType.SECRET_CHUNK,
        secret=True,
    )
    buffer = cast(bytearray, payload)
    failed = False
    try:
        if len(buffer) < _CHUNK_ORDINAL.size:
            raise ContainerAttachError("secret_chunk")
        ordinal = _CHUNK_ORDINAL.unpack(bytes(buffer[: _CHUNK_ORDINAL.size]))[0]
        if ordinal != expected_ordinal:
            raise ContainerAttachError("secret_chunk")
        for index in range(_CHUNK_ORDINAL.size):
            buffer[index] = 0
        del buffer[: _CHUNK_ORDINAL.size]
    except (ContainerAttachError, struct.error):
        failed = True
    if failed:
        _zeroize(buffer)
        raise ContainerAttachError("secret_chunk")
    return buffer


def _require_protocol_and_request(
    protocol: ContainerBootstrapAttachProtocolV1,
    request: ContainerAttachRequestV1,
) -> tuple[ContainerBootstrapAttachProtocolV1, ContainerAttachRequestV1]:
    checked_protocol = _strict_model(
        protocol, ContainerBootstrapAttachProtocolV1, phase="attach_protocol"
    )
    checked_request = _strict_model(request, ContainerAttachRequestV1, phase="attach_request")
    try:
        descriptor_bytes = sum(field.encoded_byte_count for field in checked_request.fields)
    except TypeError:
        raise ContainerAttachError("attach_request") from None
    if (
        checked_request.attach_protocol_sha256
        != container_bootstrap_attach_protocol_sha256(checked_protocol)
        or checked_request.operation_scope not in checked_protocol.allowed_operation_scopes
        or checked_request.expected_ready_state != checked_protocol.ready_state
        or checked_request.expected_claim_state != checked_protocol.claim_state
        or checked_request.expected_terminal_ack_state != checked_protocol.terminal_ack_state
        or len(checked_request.fields) > checked_protocol.max_chunks_per_target
        or descriptor_bytes > checked_protocol.max_total_secret_bytes
        or any(
            field.encoded_byte_count > checked_protocol.max_chunk_bytes
            for field in checked_request.fields
        )
    ):
        raise ContainerAttachError("attach_request")
    return checked_protocol, checked_request


def _request_metadata(request: ContainerAttachRequestV1) -> bytes:
    return _canonical_metadata(request)


def read_container_attach_request(
    reader: AttachByteReader,
    *,
    protocol: ContainerBootstrapAttachProtocolV1,
    expected_request: ContainerAttachRequestV1,
) -> ContainerAttachRequestV1:
    """Read and exactly bind a wrapper-side request before any readiness ack.

    The caller supplies its independently reconstructed signed target request.
    Equality is checked only after strict canonical revalidation, so a raw
    enum/string replacement, nonce substitution, component swap, or changed
    image/wrapper binding cannot become local attach authority.
    """

    checked_protocol, checked_expected = _require_protocol_and_request(protocol, expected_request)
    incoming = _read_metadata(
        reader,
        protocol=checked_protocol,
        frame_type=ContainerAttachFrameType.REQUEST,
        model_type=ContainerAttachRequestV1,
        phase="attach_request",
    )
    _, checked_incoming = _require_protocol_and_request(checked_protocol, incoming)
    if checked_incoming != checked_expected or not _same_exact_shape(
        checked_incoming, checked_expected
    ):
        raise ContainerAttachError("attach_request")
    return checked_incoming


def _expected_claim(request: ContainerAttachRequestV1) -> ContainerAttachClaimV1:
    return ContainerAttachClaimV1(
        schema_version="rsd.container-attach-claim.v1",
        request_sha256=container_attach_request_sha256(request),
        state="claimed_v1",
        chunk_count=len(request.fields),
        chunk_descriptors_sha256=container_attach_chunk_descriptors_sha256(request.fields),
        eof_required_after_terminal_ack=True,
    )


def _validate_ready(
    ready: ContainerAttachReadyV1,
    *,
    request: ContainerAttachRequestV1,
) -> None:
    if (
        ready.request_sha256 != container_attach_request_sha256(request)
        or ready.component != request.component
        or ready.container_id != request.container_id
        or ready.state != request.expected_ready_state
        or ready.wrapper_artifact_binding_sha256 != request.wrapper_artifact_binding_sha256
        or ready.attach_protocol_sha256 != request.attach_protocol_sha256
    ):
        raise ContainerAttachError("ready")


def _validate_claim(
    claim: ContainerAttachClaimV1,
    *,
    request: ContainerAttachRequestV1,
) -> None:
    expected = _expected_claim(request)
    if claim != expected:
        raise ContainerAttachError("claim")


def _validate_ack(
    ack: ContainerAttachTerminalAckV1,
    *,
    request: ContainerAttachRequestV1,
) -> None:
    expected_claim = _expected_claim(request)
    if (
        ack.request_sha256 != expected_claim.request_sha256
        or ack.state != request.expected_terminal_ack_state
        or ack.chunk_count != expected_claim.chunk_count
        or ack.chunk_descriptors_sha256 != expected_claim.chunk_descriptors_sha256
        or ack.chunks_zeroized is not True
        or ack.persistence_allowed is not False
        or ack.logging_allowed is not False
        or ack.receipt_contains_secret is not False
        or ack.eof_observed is not True
    ):
        raise ContainerAttachError("terminal_ack")


@dataclass(slots=True, repr=False)
class ContainerAttachDelivery:
    """Ephemeral receiver-side buffers for exactly one target attach request."""

    _fields: tuple[TargetDeliveryFieldV1, ...] = field(repr=False)
    _buffers: tuple[bytearray, ...] = field(repr=False)
    _consumed: bool = field(default=False, init=False, repr=False)

    @property
    def chunk_count(self) -> int:
        """Return receipt-safe delivery metadata without exposing chunk bytes."""

        return len(self._fields)

    def consume_into(self, sink: ContainerAttachSecretSink) -> None:
        """Provide chunks once to the exact target capability and zeroize them."""

        if self._consumed:
            raise ContainerAttachError("delivery_reused")
        self._consumed = True
        failed = False
        try:
            for descriptor, buffer in zip(self._fields, self._buffers, strict=True):
                sink.accept(descriptor, memoryview(buffer))
        except Exception:
            failed = True
        finally:
            for buffer in self._buffers:
                _zeroize(buffer)
        if failed:
            raise ContainerAttachError("target_sink")

    def abandon(self) -> None:
        """Zeroize a never-consumed delivery after a fail-closed abort."""

        if not self._consumed:
            self._consumed = True
            for buffer in self._buffers:
                _zeroize(buffer)


def read_secret_chunks(
    reader: AttachByteReader,
    *,
    protocol: ContainerBootstrapAttachProtocolV1,
    request: ContainerAttachRequestV1,
    claim: ContainerAttachClaimV1,
) -> ContainerAttachDelivery:
    """Read the one exact ordered secret sequence for a validated local claim.

    This target-side helper does not return a mapping, values, or wire bytes;
    callers must consume the returned capability once and then emit a redacted
    terminal acknowledgement through their own future wrapper implementation.
    """

    checked_protocol, checked_request = _require_protocol_and_request(protocol, request)
    checked_claim = _strict_model(claim, ContainerAttachClaimV1, phase="claim")
    _validate_claim(checked_claim, request=checked_request)
    buffers: list[bytearray] = []
    failed = False
    try:
        for descriptor in checked_request.fields:
            buffer = _read_secret_chunk(
                reader,
                protocol=checked_protocol,
                expected_ordinal=descriptor.ordinal,
            )
            if len(buffer) != descriptor.encoded_byte_count:
                _zeroize(buffer)
                raise ContainerAttachError("secret_chunk")
            buffers.append(buffer)
    except Exception:
        failed = True
    if failed:
        for buffer in buffers:
            _zeroize(buffer)
        raise ContainerAttachError("secret_chunk")
    return ContainerAttachDelivery(checked_request.fields, tuple(buffers))


class ContainerAttachDaemonSession:
    """One non-retryable daemon-side local attach state machine.

    Once the first chunk is attempted, every framing, acknowledgement, or EOF
    failure becomes ``AMBIGUOUS``.  The caller must record that terminal state
    and obtain fresh signed authorization; this object intentionally offers no
    retry, resume, adoption, or replay path.
    """

    __slots__ = ("_protocol", "_request", "_state")

    def __init__(
        self,
        *,
        protocol: ContainerBootstrapAttachProtocolV1,
        request: ContainerAttachRequestV1,
    ) -> None:
        self._protocol, self._request = _require_protocol_and_request(protocol, request)
        self._state = ContainerAttachSessionState.NEW

    @property
    def state(self) -> ContainerAttachSessionState:
        """Return the value-free monotonic session state."""

        return self._state

    @property
    def expected_claim(self) -> ContainerAttachClaimV1:
        """Return the only claim metadata this session will emit."""

        return _expected_claim(self._request)

    def write_request(self, writer: AttachByteWriter) -> None:
        if self._state is not ContainerAttachSessionState.NEW:
            raise ContainerAttachError("state")
        _write_frame(
            writer,
            protocol=self._protocol,
            frame_type=ContainerAttachFrameType.REQUEST,
            payload=_request_metadata(self._request),
            secret=False,
        )
        self._state = ContainerAttachSessionState.REQUEST_SENT

    def read_ready(self, reader: AttachByteReader) -> ContainerAttachReadyV1:
        if self._state is not ContainerAttachSessionState.REQUEST_SENT:
            raise ContainerAttachError("state")
        ready = _read_metadata(
            reader,
            protocol=self._protocol,
            frame_type=ContainerAttachFrameType.READY,
            model_type=ContainerAttachReadyV1,
            phase="ready",
        )
        _validate_ready(ready, request=self._request)
        self._state = ContainerAttachSessionState.READY_RECEIVED
        return ready

    def write_claim(self, writer: AttachByteWriter) -> ContainerAttachClaimV1:
        if self._state is not ContainerAttachSessionState.READY_RECEIVED:
            raise ContainerAttachError("state")
        claim = _expected_claim(self._request)
        _write_frame(
            writer,
            protocol=self._protocol,
            frame_type=ContainerAttachFrameType.CLAIM,
            payload=_canonical_metadata(claim),
            secret=False,
        )
        self._state = ContainerAttachSessionState.CLAIM_SENT
        return claim

    def write_secret_chunks(
        self,
        writer: AttachByteWriter,
        chunks: tuple[bytearray, ...],
    ) -> None:
        """Stream mutable chunks once, in signed order, then zeroize all input."""

        buffers = chunks if type(chunks) is tuple else ()
        failure_phase: str | None = None
        try:
            if self._state is not ContainerAttachSessionState.CLAIM_SENT:
                raise ContainerAttachError("state")
            if len(chunks) != len(self._request.fields) or any(
                type(chunk) is not bytearray for chunk in chunks
            ):
                raise ContainerAttachError("secret_chunks")
            self._state = ContainerAttachSessionState.CHUNKS_SENT
            for descriptor, chunk in zip(self._request.fields, chunks, strict=True):
                if len(chunk) != descriptor.encoded_byte_count:
                    raise ContainerAttachError("secret_chunk")
                _write_secret_frame(
                    writer,
                    protocol=self._protocol,
                    ordinal=descriptor.ordinal,
                    chunk=chunk,
                )
        except ContainerAttachError as error:
            failure_phase = error.phase
        except Exception:
            failure_phase = "secret_chunk"
        finally:
            for buffer in buffers:
                if type(buffer) is bytearray:
                    _zeroize(buffer)
        if failure_phase is not None:
            self._state = ContainerAttachSessionState.AMBIGUOUS
            raise ContainerAttachError(failure_phase)

    def read_terminal_ack(self, reader: AttachByteReader) -> ContainerAttachTerminalAckV1:
        if self._state is not ContainerAttachSessionState.CHUNKS_SENT:
            raise ContainerAttachError("state")
        failure_phase: str | None = None
        ack: ContainerAttachTerminalAckV1 | None = None
        try:
            ack = _read_metadata(
                reader,
                protocol=self._protocol,
                frame_type=ContainerAttachFrameType.TERMINAL_ACK,
                model_type=ContainerAttachTerminalAckV1,
                phase="terminal_ack",
            )
            _validate_ack(ack, request=self._request)
        except ContainerAttachError as error:
            failure_phase = error.phase
        if failure_phase is not None:
            self._state = ContainerAttachSessionState.AMBIGUOUS
            raise ContainerAttachError(failure_phase)
        if ack is None:
            self._state = ContainerAttachSessionState.AMBIGUOUS
            raise ContainerAttachError("terminal_ack")
        self._state = ContainerAttachSessionState.TERMINAL_ACK_RECEIVED
        return ack

    def require_eof(self, reader: AttachByteReader) -> None:
        """Require the terminal clean EOF after a redacted terminal ack."""

        if self._state is not ContainerAttachSessionState.TERMINAL_ACK_RECEIVED:
            raise ContainerAttachError("state")
        failure_phase: str | None = None
        try:
            trailing = reader.read(1)
            if type(trailing) is not bytes or trailing != b"":
                raise ContainerAttachError("trailing_data")
        except ContainerAttachError as error:
            failure_phase = error.phase
        except Exception:
            failure_phase = "eof"
        if failure_phase is not None:
            self._state = ContainerAttachSessionState.AMBIGUOUS
            raise ContainerAttachError(failure_phase)
        self._state = ContainerAttachSessionState.CLOSED
