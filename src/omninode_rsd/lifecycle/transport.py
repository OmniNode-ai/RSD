"""Bounded, versioned framing for value-free control metadata and secret chunks.

This module deliberately stops at bytes.  It does not open sockets, invoke
processes, access a keychain, or emit logs.  Metadata carries only identifiers
and protocol bindings; secret material is carried as opaque binary chunks and
is never interpolated into an exception message.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal, Protocol
from uuid import UUID

FRAME_MAGIC: Final[bytes] = b"ONXR"
FRAME_VERSION: Final[int] = 1
FRAME_HEADER_BYTES: Final[int] = 14
MAX_TOTAL_BYTES: Final[int] = 1_048_576
# A complete typed executor receipt includes four filtered container
# inspections.  Keep the envelope strictly bounded while allowing that
# redacted evidence to remain canonical metadata rather than being split into
# an untyped side channel.
MAX_METADATA_BYTES: Final[int] = 16_384
MAX_CHUNK_BYTES: Final[int] = 65_536
MAX_CHUNKS: Final[int] = 64

_HEADER = struct.Struct("!4sBBII")
_SCHEMA_VERSION: Final[Literal["rsd.transport.metadata.v1"]] = "rsd.transport.metadata.v1"
_METADATA_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "message_type",
        "client_nonce",
        "server_nonce",
        "session_id",
        "operation_id",
        "request_id",
        "chunk_count",
    }
)


class TransportError(ValueError):
    """Raised when a frame stream is invalid or exceeds a bound."""


class TransportMessageType(StrEnum):
    """Control operation represented by a metadata frame."""

    HELLO = "hello"
    START = "start"
    MATERIALIZE = "materialize"


@dataclass(frozen=True, slots=True)
class TransportMetadata:
    """Value-free identifiers binding one framed control operation.

    ``server_nonce`` is nullable for a client Hello, where the server has not
    yet contributed its nonce.  Start and Materialize metadata require it.
    All five identifiers are UUIDs rather than arbitrary strings so callers
    cannot accidentally place credentials or other material in this frame.
    """

    message_type: TransportMessageType
    client_nonce: UUID
    server_nonce: UUID | None
    session_id: UUID
    operation_id: UUID
    request_id: UUID
    chunk_count: int

    def __post_init__(self) -> None:
        if type(self.message_type) is not TransportMessageType:
            raise TransportError("message type is invalid")
        for value in (
            self.client_nonce,
            self.session_id,
            self.operation_id,
            self.request_id,
        ):
            if type(value) is not UUID:
                raise TransportError("metadata binding is invalid")
        if self.server_nonce is not None and type(self.server_nonce) is not UUID:
            raise TransportError("metadata binding is invalid")
        if self.message_type is not TransportMessageType.HELLO and self.server_nonce is None:
            raise TransportError("server nonce is required")
        if type(self.chunk_count) is not int or not 0 <= self.chunk_count <= MAX_CHUNKS:
            raise TransportError("chunk count exceeds the protocol bound")

    @classmethod
    def hello(
        cls,
        *,
        client_nonce: UUID,
        server_nonce: UUID | None = None,
        session_id: UUID,
        operation_id: UUID,
        request_id: UUID,
        chunk_count: int = 0,
    ) -> TransportMetadata:
        """Construct a Hello binding before a server nonce exists."""

        return cls(
            message_type=TransportMessageType.HELLO,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            session_id=session_id,
            operation_id=operation_id,
            request_id=request_id,
            chunk_count=chunk_count,
        )

    @classmethod
    def start(
        cls,
        *,
        client_nonce: UUID,
        server_nonce: UUID,
        session_id: UUID,
        operation_id: UUID,
        request_id: UUID,
        chunk_count: int = 0,
    ) -> TransportMetadata:
        """Construct a Start binding with both protocol nonces."""

        return cls(
            message_type=TransportMessageType.START,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            session_id=session_id,
            operation_id=operation_id,
            request_id=request_id,
            chunk_count=chunk_count,
        )

    @classmethod
    def materialize(
        cls,
        *,
        client_nonce: UUID,
        server_nonce: UUID,
        session_id: UUID,
        operation_id: UUID,
        request_id: UUID,
        chunk_count: int = 0,
    ) -> TransportMetadata:
        """Construct a Materialize binding with both protocol nonces."""

        return cls(
            message_type=TransportMessageType.MATERIALIZE,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            session_id=session_id,
            operation_id=operation_id,
            request_id=request_id,
            chunk_count=chunk_count,
        )

    def _mapping(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "message_type": self.message_type.value,
            "client_nonce": str(self.client_nonce),
            "server_nonce": None if self.server_nonce is None else str(self.server_nonce),
            "session_id": str(self.session_id),
            "operation_id": str(self.operation_id),
            "request_id": str(self.request_id),
            "chunk_count": self.chunk_count,
        }


@dataclass(frozen=True, slots=True)
class MetadataFrame:
    """Decoded metadata frame."""

    metadata: TransportMetadata


@dataclass(frozen=True, slots=True)
class SecretChunkFrame:
    """Decoded opaque binary secret chunk frame."""

    sequence: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class DecodedTransport:
    """Complete decoded stream, retaining metadata before opaque chunks."""

    metadata: TransportMetadata
    chunks: tuple[bytes, ...]


type DecodedFrame = MetadataFrame | SecretChunkFrame


@dataclass(frozen=True, slots=True)
class RawDecodedTransport:
    """Canonical metadata bytes plus opaque chunks for a higher typed layer.

    The codec does not interpret the metadata beyond canonical JSON.  The
    remote executor layer immediately validates the bytes as one exact signed
    model before it accepts a chunk, so values can never become a generic
    metadata interface.
    """

    metadata_bytes: bytes
    chunks: tuple[bytes, ...]


class FrameByteWriter(Protocol):
    """Minimal binary sink used for direct secret streaming."""

    def write(self, data: bytes | memoryview) -> int | None: ...

    def flush(self) -> object: ...


class FrameByteReader(Protocol):
    """Minimal exact-read source used by a bounded request/response session."""

    def read_exact(self, count: int) -> bytes: ...


class FinalFrameBoundary(Protocol):
    """Final-stream boundary required for a terminal protocol message."""

    def require_eof(self) -> None: ...


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _canonical_metadata_bytes(payload: bytes) -> None:
    """Reject noncanonical JSON without surfacing decoded fields in errors."""

    if type(payload) is not bytes or not payload or len(payload) > MAX_METADATA_BYTES:
        raise TransportError("metadata size exceeds the protocol bound")
    try:
        decoded = json.loads(payload.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TransportError("metadata is not canonical JSON") from None
    if type(decoded) is not dict or _canonical_json(decoded) != payload:
        raise TransportError("metadata is not canonical JSON")


def _parse_uuid(value: object) -> UUID:
    if type(value) is not str:
        raise TransportError("metadata binding is invalid")
    try:
        result = UUID(value)
    except (ValueError, AttributeError):
        raise TransportError("metadata binding is invalid") from None
    if str(result) != value:
        raise TransportError("metadata binding is not canonical")
    return result


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TransportError("metadata contains duplicate fields")
        result[key] = value
    return result


def _decode_metadata(payload: bytes) -> TransportMetadata:
    if not payload or len(payload) > MAX_METADATA_BYTES:
        raise TransportError("metadata size exceeds the protocol bound")
    try:
        decoded = json.loads(payload.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TransportError("metadata is not canonical JSON") from None
    if type(decoded) is not dict or frozenset(decoded) != _METADATA_KEYS:
        raise TransportError("metadata fields are invalid")
    if _canonical_json(decoded) != payload:
        raise TransportError("metadata is not canonical JSON")
    if decoded["schema_version"] != _SCHEMA_VERSION:
        raise TransportError("metadata schema version is invalid")
    message_type = decoded["message_type"]
    if type(message_type) is not str:
        raise TransportError("message type is invalid")
    try:
        typed_message_type = TransportMessageType(message_type)
    except ValueError:
        raise TransportError("message type is invalid") from None
    chunk_count = decoded["chunk_count"]
    if type(chunk_count) is not int:
        raise TransportError("chunk count is invalid")
    server_value = decoded["server_nonce"]
    server_nonce = None if server_value is None else _parse_uuid(server_value)
    return TransportMetadata(
        message_type=typed_message_type,
        client_nonce=_parse_uuid(decoded["client_nonce"]),
        server_nonce=server_nonce,
        session_id=_parse_uuid(decoded["session_id"]),
        operation_id=_parse_uuid(decoded["operation_id"]),
        request_id=_parse_uuid(decoded["request_id"]),
        chunk_count=chunk_count,
    )


def _validate_chunk(payload: bytes) -> None:
    if type(payload) is not bytes or not payload:
        raise TransportError("secret chunk type is invalid")
    if len(payload) > MAX_CHUNK_BYTES:
        raise TransportError("secret chunk exceeds the protocol bound")


def _frame(kind: int, sequence: int, payload: bytes) -> bytes:
    header = _HEADER.pack(FRAME_MAGIC, FRAME_VERSION, kind, sequence, len(payload))
    return header + payload


def encode_transport(metadata: TransportMetadata, chunks: tuple[bytes, ...]) -> bytes:
    """Encode one complete metadata-plus-chunk stream."""

    if type(metadata) is not TransportMetadata:
        raise TransportError("metadata type is invalid")
    if type(chunks) is not tuple:
        raise TransportError("chunks type is invalid")
    if len(chunks) != metadata.chunk_count:
        raise TransportError("chunk count does not match metadata")
    metadata_payload = _canonical_json(metadata._mapping())
    if len(metadata_payload) > MAX_METADATA_BYTES:
        raise TransportError("metadata size exceeds the protocol bound")
    encoded = bytearray(_frame(1, 0, metadata_payload))
    for sequence, chunk in enumerate(chunks, 1):
        _validate_chunk(chunk)
        encoded.extend(_frame(2, sequence, chunk))
        if len(encoded) > MAX_TOTAL_BYTES:
            raise TransportError("transport exceeds the total size bound")
    if len(encoded) > MAX_TOTAL_BYTES:
        raise TransportError("transport exceeds the total size bound")
    return bytes(encoded)


class TransportDecoder:
    """Incremental decoder enforcing framing, size, and sequence invariants."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._received = 0
        self._metadata: TransportMetadata | None = None
        self._next_sequence = 0
        self._frames: list[DecodedFrame] = []
        self._closed = False

    def feed(self, data: bytes) -> tuple[DecodedFrame, ...]:
        """Consume bytes and return complete frames; incomplete input is retained."""

        if self._closed:
            raise TransportError("decoder is already closed")
        if type(data) is not bytes:
            raise TransportError("transport input type is invalid")
        if self._received + len(data) > MAX_TOTAL_BYTES:
            raise TransportError("transport exceeds the total size bound")
        self._received += len(data)
        self._buffer.extend(data)
        start = len(self._frames)
        while len(self._buffer) >= FRAME_HEADER_BYTES:
            magic, version, kind, sequence, payload_length = _HEADER.unpack(
                self._buffer[:FRAME_HEADER_BYTES]
            )
            if magic != FRAME_MAGIC or version != FRAME_VERSION:
                raise TransportError("frame header is invalid")
            if kind not in (1, 2):
                raise TransportError("frame type is unknown")
            if payload_length > (MAX_METADATA_BYTES if kind == 1 else MAX_CHUNK_BYTES):
                raise TransportError("frame payload exceeds its bound")
            frame_length = FRAME_HEADER_BYTES + payload_length
            if len(self._buffer) < frame_length:
                break
            payload = bytes(self._buffer[FRAME_HEADER_BYTES:frame_length])
            del self._buffer[:frame_length]
            if self._metadata is None:
                if kind != 1 or sequence != 0:
                    raise TransportError("metadata frame must be first")
                self._metadata = _decode_metadata(payload)
                self._next_sequence = 1
                self._frames.append(MetadataFrame(self._metadata))
                continue
            if kind != 2 or sequence != self._next_sequence:
                raise TransportError("secret chunk order is invalid")
            _validate_chunk(payload)
            if self._next_sequence > self._metadata.chunk_count:
                raise TransportError("secret chunk count exceeds metadata")
            self._frames.append(SecretChunkFrame(sequence, payload))
            self._next_sequence += 1
        return tuple(self._frames[start:])

    def finish(self) -> DecodedTransport:
        """Close the stream, rejecting partial frames or missing chunks."""

        if self._closed:
            raise TransportError("decoder is already closed")
        self._closed = True
        if self._buffer:
            raise TransportError("transport ended with a partial frame")
        if self._metadata is None:
            raise TransportError("metadata frame is missing")
        if self._next_sequence - 1 != self._metadata.chunk_count:
            raise TransportError("transport ended before all chunks")
        return DecodedTransport(
            metadata=self._metadata,
            chunks=tuple(
                frame.payload for frame in self._frames if isinstance(frame, SecretChunkFrame)
            ),
        )


def decode_transport(data: bytes) -> DecodedTransport:
    """Decode one complete stream and reject any trailing or partial bytes."""

    decoder = TransportDecoder()
    decoder.feed(data)
    return decoder.finish()


class FramedTransportCodec:
    """Stateless convenience facade for complete encode/decode operations."""

    encode = staticmethod(encode_transport)
    decode = staticmethod(decode_transport)


class CanonicalFrameWriter:
    """Stream canonical metadata and one ordered sequence of opaque chunks.

    This writer never collects secret chunks into a mapping or a combined
    buffer.  Each caller-owned mutable buffer is written directly after a
    bounded frame header and should be overwritten by its owner immediately
    afterwards.
    """

    def __init__(self, sink: FrameByteWriter) -> None:
        if not hasattr(sink, "write") or not hasattr(sink, "flush"):
            raise TransportError("frame writer is invalid")
        self._sink = sink
        self._expected = 0
        self._next = 1
        self._begun = False
        self._finished = False
        self._total = 0

    def _write(self, value: bytes | memoryview) -> None:
        try:
            result = self._sink.write(value)
            if result is not None and result != len(value):
                raise ValueError
            self._sink.flush()
        except Exception:
            raise TransportError("frame writer failed") from None
        self._total += len(value)
        if self._total > MAX_TOTAL_BYTES:
            raise TransportError("transport exceeds the total size bound")

    def begin(self, metadata_bytes: bytes, *, chunk_count: int) -> None:
        if self._begun or self._finished or type(chunk_count) is not int:
            raise TransportError("frame writer state is invalid")
        if not 0 <= chunk_count <= MAX_CHUNKS:
            raise TransportError("chunk count exceeds the protocol bound")
        _canonical_metadata_bytes(metadata_bytes)
        self._write(_frame(1, 0, metadata_bytes))
        self._expected = chunk_count
        self._begun = True

    def write_chunk(self, payload: memoryview) -> None:
        if not self._begun or self._finished or self._next > self._expected:
            raise TransportError("frame writer state is invalid")
        if type(payload) is not memoryview or payload.ndim != 1 or not payload.contiguous:
            raise TransportError("secret chunk type is invalid")
        if not payload or len(payload) > MAX_CHUNK_BYTES:
            raise TransportError("secret chunk exceeds the protocol bound")
        self._write(_HEADER.pack(FRAME_MAGIC, FRAME_VERSION, 2, self._next, len(payload)))
        self._write(payload)
        self._next += 1

    def finish(self) -> None:
        if not self._begun or self._finished or self._next - 1 != self._expected:
            raise TransportError("frame writer state is invalid")
        self._finished = True


class RawTransportDecoder:
    """Incrementally decode canonical metadata bytes and opaque ordered chunks."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._received = 0
        self._metadata: bytes | None = None
        self._expected = 0
        self._next = 1
        self._chunks: list[bytes] = []
        self._closed = False

    def feed(self, data: bytes) -> None:
        if self._closed or type(data) is not bytes:
            raise TransportError("transport input type is invalid")
        if self._received + len(data) > MAX_TOTAL_BYTES:
            raise TransportError("transport exceeds the total size bound")
        self._received += len(data)
        self._buffer.extend(data)
        while len(self._buffer) >= FRAME_HEADER_BYTES:
            magic, version, kind, sequence, payload_length = _HEADER.unpack(
                self._buffer[:FRAME_HEADER_BYTES]
            )
            if magic != FRAME_MAGIC or version != FRAME_VERSION:
                raise TransportError("frame header is invalid")
            if kind not in (1, 2):
                raise TransportError("frame type is unknown")
            limit = MAX_METADATA_BYTES if kind == 1 else MAX_CHUNK_BYTES
            if payload_length > limit:
                raise TransportError("frame payload exceeds its bound")
            frame_length = FRAME_HEADER_BYTES + payload_length
            if len(self._buffer) < frame_length:
                return
            payload = bytes(self._buffer[FRAME_HEADER_BYTES:frame_length])
            del self._buffer[:frame_length]
            if self._metadata is None:
                if kind != 1 or sequence != 0:
                    raise TransportError("metadata frame must be first")
                _canonical_metadata_bytes(payload)
                self._metadata = payload
                try:
                    decoded = json.loads(payload.decode("ascii"))
                    count = decoded.get("chunk_count") if type(decoded) is dict else None
                except (UnicodeDecodeError, json.JSONDecodeError):
                    count = None
                if type(count) is not int or not 0 <= count <= MAX_CHUNKS:
                    raise TransportError("chunk count is invalid")
                self._expected = count
                continue
            if kind != 2 or sequence != self._next:
                raise TransportError("secret chunk order is invalid")
            _validate_chunk(payload)
            if self._next > self._expected:
                raise TransportError("secret chunk count exceeds metadata")
            self._chunks.append(payload)
            self._next += 1

    def finish(self) -> RawDecodedTransport:
        if self._closed:
            raise TransportError("decoder is already closed")
        self._closed = True
        if self._buffer:
            raise TransportError("transport ended with a partial frame")
        if self._metadata is None or self._next - 1 != self._expected:
            raise TransportError("transport ended before all chunks")
        return RawDecodedTransport(metadata_bytes=self._metadata, chunks=tuple(self._chunks))


class CanonicalFrameReader:
    """Read metadata first, then exactly ordered opaque chunks on demand.

    A daemon uses this split to persist a replay claim after validating signed
    metadata and before it asks its source for even one material chunk.
    """

    def __init__(self, source: FrameByteReader) -> None:
        if not hasattr(source, "read_exact"):
            raise TransportError("frame reader is invalid")
        self._source = source
        self._expected: int | None = None
        self._next = 1
        self._finished = False
        self._total = 0

    def _read_exact(self, count: int) -> bytes:
        """Read one bounded segment while enforcing the whole-group limit."""

        if type(count) is not int or count < 0:
            raise TransportError("frame reader state is invalid")
        try:
            value = self._source.read_exact(count)
        except Exception:
            raise TransportError("frame reader failed") from None
        if type(value) is not bytes or len(value) != count:
            raise TransportError("frame reader failed")
        self._total += count
        if self._total > MAX_TOTAL_BYTES:
            raise TransportError("transport exceeds the total size bound")
        return value

    def read_metadata(self) -> bytes:
        if self._expected is not None or self._finished:
            raise TransportError("frame reader state is invalid")
        try:
            header = self._read_exact(FRAME_HEADER_BYTES)
            magic, version, kind, sequence, size = _HEADER.unpack(header)
            if (
                magic != FRAME_MAGIC
                or version != FRAME_VERSION
                or kind != 1
                or sequence != 0
                or size > MAX_METADATA_BYTES
            ):
                raise ValueError
            payload = self._read_exact(size)
            _canonical_metadata_bytes(payload)
            decoded = json.loads(payload.decode("ascii"))
            count = decoded.get("chunk_count") if type(decoded) is dict else None
            if type(count) is not int or not 0 <= count <= MAX_CHUNKS:
                raise ValueError
            self._expected = count
            return payload
        except TransportError:
            raise
        except Exception:
            raise TransportError("frame reader failed") from None

    def read_chunk(self) -> bytes:
        if self._expected is None or self._finished or self._next > self._expected:
            raise TransportError("frame reader state is invalid")
        try:
            header = self._read_exact(FRAME_HEADER_BYTES)
            magic, version, kind, sequence, size = _HEADER.unpack(header)
            if (
                magic != FRAME_MAGIC
                or version != FRAME_VERSION
                or kind != 2
                or sequence != self._next
                or size > MAX_CHUNK_BYTES
            ):
                raise ValueError
            payload = self._read_exact(size)
            _validate_chunk(payload)
            self._next += 1
            return payload
        except TransportError:
            raise
        except Exception:
            raise TransportError("frame reader failed") from None

    def finish(self) -> None:
        if self._expected is None or self._finished or self._next - 1 != self._expected:
            raise TransportError("frame reader state is invalid")
        self._finished = True


def read_raw_transport(
    source: FrameByteReader,
    *,
    require_eof: bool = True,
) -> RawDecodedTransport:
    """Read one raw stream and require final EOF unless another group follows.

    A terminal protocol response must end at an authenticated EOF. Callers
    reading the first group of a fixed multi-group dialogue must opt out
    explicitly; this makes accepting appended unknown or duplicate frames an
    intentional, tightly scoped choice rather than the default parser mode.
    """

    if type(require_eof) is not bool or not hasattr(source, "read_exact"):
        raise TransportError("frame reader is invalid")
    decoder = RawTransportDecoder()
    try:
        header = source.read_exact(FRAME_HEADER_BYTES)
        if len(header) != FRAME_HEADER_BYTES:
            raise ValueError
        magic, version, kind, sequence, size = _HEADER.unpack(header)
        if (
            magic != FRAME_MAGIC
            or version != FRAME_VERSION
            or kind != 1
            or sequence != 0
            or size > MAX_METADATA_BYTES
        ):
            raise ValueError
        decoder.feed(header + source.read_exact(size))
        metadata = decoder._metadata
        if metadata is None:
            raise ValueError
        decoded = json.loads(metadata.decode("ascii"))
        count = decoded.get("chunk_count") if type(decoded) is dict else None
        if type(count) is not int or not 0 <= count <= MAX_CHUNKS:
            raise ValueError
        for expected in range(1, count + 1):
            header = source.read_exact(FRAME_HEADER_BYTES)
            if len(header) != FRAME_HEADER_BYTES:
                raise ValueError
            magic, version, kind, sequence, size = _HEADER.unpack(header)
            if (
                magic != FRAME_MAGIC
                or version != FRAME_VERSION
                or kind != 2
                or sequence != expected
                or size > MAX_CHUNK_BYTES
            ):
                raise ValueError
            decoder.feed(header + source.read_exact(size))
        result = decoder.finish()
        if require_eof:
            finalizer = getattr(source, "require_eof", None)
            if not callable(finalizer):
                raise ValueError
            finalizer()
        return result
    except TransportError:
        raise
    except Exception:
        raise TransportError("frame reader failed") from None


__all__ = [
    "FRAME_HEADER_BYTES",
    "FRAME_MAGIC",
    "FRAME_VERSION",
    "MAX_CHUNKS",
    "MAX_CHUNK_BYTES",
    "MAX_METADATA_BYTES",
    "MAX_TOTAL_BYTES",
    "CanonicalFrameReader",
    "CanonicalFrameWriter",
    "DecodedFrame",
    "DecodedTransport",
    "FinalFrameBoundary",
    "FrameByteReader",
    "FrameByteWriter",
    "FramedTransportCodec",
    "MetadataFrame",
    "RawDecodedTransport",
    "RawTransportDecoder",
    "SecretChunkFrame",
    "TransportDecoder",
    "TransportError",
    "TransportMessageType",
    "TransportMetadata",
    "decode_transport",
    "encode_transport",
    "read_raw_transport",
]
