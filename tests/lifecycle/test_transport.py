"""Adversarial tests for the bounded public transport frame codec."""

from __future__ import annotations

import json
import struct
from uuid import UUID

import pytest

from omninode_rsd.lifecycle.transport import (
    FRAME_HEADER_BYTES,
    FRAME_MAGIC,
    FRAME_VERSION,
    MAX_CHUNK_BYTES,
    MAX_CHUNKS,
    MAX_METADATA_BYTES,
    MAX_TOTAL_BYTES,
    CanonicalFrameReader,
    FramedTransportCodec,
    TransportDecoder,
    TransportError,
    TransportMetadata,
    decode_transport,
    encode_transport,
    read_raw_transport,
)

_HEADER = struct.Struct("!4sBBII")
_CLIENT = UUID("00000000-0000-0000-0000-000000000001")
_SERVER = UUID("00000000-0000-0000-0000-000000000002")
_SESSION = UUID("00000000-0000-0000-0000-000000000003")
_OPERATION = UUID("00000000-0000-0000-0000-000000000004")
_REQUEST = UUID("00000000-0000-0000-0000-000000000005")


def _metadata(*, count: int = 2) -> TransportMetadata:
    return TransportMetadata.start(
        client_nonce=_CLIENT,
        server_nonce=_SERVER,
        session_id=_SESSION,
        operation_id=_OPERATION,
        request_id=_REQUEST,
        chunk_count=count,
    )


def _frame(kind: int, sequence: int, payload: bytes) -> bytes:
    return _HEADER.pack(FRAME_MAGIC, FRAME_VERSION, kind, sequence, len(payload)) + payload


def test_round_trip_preserves_canonical_metadata_and_binary_chunks() -> None:
    encoded = encode_transport(_metadata(), (b"secret\x00one", b"secret\xfftwo"))

    decoded = decode_transport(encoded)

    assert decoded.metadata == _metadata()
    assert decoded.chunks == (b"secret\x00one", b"secret\xfftwo")
    assert FramedTransportCodec.decode(
        FramedTransportCodec.encode(_metadata(), (b"a", b"b"))
    ) == decoded.__class__(metadata=_metadata(), chunks=(b"a", b"b"))


@pytest.mark.parametrize(
    "metadata",
    (
        TransportMetadata.hello(
            client_nonce=_CLIENT,
            session_id=_SESSION,
            operation_id=_OPERATION,
            request_id=_REQUEST,
        ),
        TransportMetadata.materialize(
            client_nonce=_CLIENT,
            server_nonce=_SERVER,
            session_id=_SESSION,
            operation_id=_OPERATION,
            request_id=_REQUEST,
        ),
    ),
)
def test_hello_and_materialize_have_typed_nonce_bindings(
    metadata: TransportMetadata,
) -> None:
    assert decode_transport(encode_transport(metadata, ())).metadata == metadata


def test_incremental_decoder_requires_metadata_first_and_complete_chunks() -> None:
    encoded = encode_transport(_metadata(), (b"a", b"b"))
    decoder = TransportDecoder()

    assert decoder.feed(encoded[:3]) == ()
    assert decoder.feed(encoded[3:-1])
    with pytest.raises(TransportError, match="partial frame"):
        decoder.finish()


@pytest.mark.parametrize(
    "stream",
    (
        _frame(2, 1, b"a"),
        _frame(1, 1, b"{}"),
        _frame(9, 0, b""),
    ),
)
def test_rejects_unknown_or_out_of_order_frames(stream: bytes) -> None:
    with pytest.raises(TransportError):
        decode_transport(stream)


def test_rejects_duplicate_and_missing_chunks() -> None:
    encoded = encode_transport(_metadata(count=1), (b"a",))
    metadata_frame = encoded[
        : FRAME_HEADER_BYTES + _HEADER.unpack(encoded[:FRAME_HEADER_BYTES])[-1]
    ]
    duplicate = encoded + encoded[metadata_frame.__len__() :]
    with pytest.raises(TransportError, match=r"order|count"):
        decode_transport(duplicate)

    zero_chunks = encode_transport(_metadata(count=1), (b"a",))[: metadata_frame.__len__()]
    with pytest.raises(TransportError, match="chunks"):
        decode_transport(zero_chunks)


def test_rejects_noncanonical_json_duplicate_and_unknown_metadata_fields() -> None:
    base = {
        "schema_version": "rsd.transport.metadata.v1",
        "message_type": "start",
        "client_nonce": str(_CLIENT),
        "server_nonce": str(_SERVER),
        "session_id": str(_SESSION),
        "operation_id": str(_OPERATION),
        "request_id": str(_REQUEST),
        "chunk_count": 0,
    }
    reordered = json.dumps(base).encode("ascii")
    unknown = dict(base, secret="must not be accepted")
    duplicate = b'{"chunk_count":0,"chunk_count":0}'
    for payload in (
        reordered,
        json.dumps(unknown, separators=(",", ":")).encode("ascii"),
        duplicate,
    ):
        with pytest.raises(TransportError):
            decode_transport(_frame(1, 0, payload))


def test_rejects_chunk_type_empty_and_oversize_inputs() -> None:
    with pytest.raises(TransportError):
        encode_transport(_metadata(count=1), (bytearray(b"a"),))  # type: ignore[arg-type]
    with pytest.raises(TransportError):
        encode_transport(_metadata(count=1), (b"",))
    with pytest.raises(TransportError):
        encode_transport(_metadata(count=1), (b"x" * (MAX_CHUNK_BYTES + 1),))
    with pytest.raises(TransportError):
        TransportMetadata.start(
            client_nonce=_CLIENT,
            server_nonce=_SERVER,
            session_id=_SESSION,
            operation_id=_OPERATION,
            request_id=_REQUEST,
            chunk_count=MAX_CHUNKS + 1,
        )


def test_rejects_declared_payload_bounds_and_total_bounds() -> None:
    metadata_frame = encode_transport(_metadata(count=0), ())
    oversized_metadata_header = _HEADER.pack(
        FRAME_MAGIC, FRAME_VERSION, 1, 0, MAX_METADATA_BYTES + 1
    )
    with pytest.raises(TransportError):
        decode_transport(oversized_metadata_header)

    chunks = tuple(b"x" * MAX_CHUNK_BYTES for _ in range(MAX_CHUNKS))
    with pytest.raises(TransportError, match="total"):
        encode_transport(_metadata(count=MAX_CHUNKS), chunks)
    assert len(metadata_frame) < MAX_TOTAL_BYTES


def test_split_reader_enforces_total_bound_before_all_declared_chunks() -> None:
    """Streaming callers get the same aggregate bound as the full decoder."""

    metadata = b'{"chunk_count":64}'
    stream = _frame(1, 0, metadata) + b"".join(
        _frame(2, sequence, b"x" * MAX_CHUNK_BYTES) for sequence in range(1, MAX_CHUNKS + 1)
    )

    class Source:
        def __init__(self, raw: bytes) -> None:
            self._raw = raw
            self._offset = 0

        def read_exact(self, count: int) -> bytes:
            value = self._raw[self._offset : self._offset + count]
            self._offset += len(value)
            return value

    reader = CanonicalFrameReader(Source(stream))
    assert reader.read_metadata() == metadata
    with pytest.raises(TransportError, match="total"):
        for _ in range(MAX_CHUNKS):
            reader.read_chunk()


def test_terminal_raw_reader_rejects_trailing_frames_at_the_eof_boundary() -> None:
    """A final receipt cannot silently ignore a duplicate trailing frame."""

    encoded = encode_transport(_metadata(count=0), ())

    class Source:
        def __init__(self, raw: bytes) -> None:
            self._raw = raw
            self._offset = 0

        def read_exact(self, count: int) -> bytes:
            value = self._raw[self._offset : self._offset + count]
            self._offset += len(value)
            return value

        def require_eof(self) -> None:
            if self._offset != len(self._raw):
                raise ValueError("trailing")

    with pytest.raises(TransportError, match="reader failed"):
        read_raw_transport(Source(encoded + encoded))
    assert read_raw_transport(Source(encoded)).metadata_bytes


def test_bad_frame_error_does_not_include_secret_bytes() -> None:
    secret = b"secret-value-that-must-not-appear"
    malformed = bytearray(encode_transport(_metadata(count=1), (secret,)))
    malformed[0] = 0

    with pytest.raises(TransportError) as caught:
        decode_transport(bytes(malformed))
    assert secret.decode("ascii") not in str(caught.value)
