"""Adversarial tests for the offline daemon-to-container attach codec.

The stream fixtures are in-memory only.  They prove framing and zeroization
rules without creating a Docker attach connection, wrapper process, provider,
database, network endpoint, or runtime workload.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import struct
from typing import cast

import pytest
from pydantic import ValidationError

from omninode_rsd.lifecycle.container_attach import (
    ContainerAttachDaemonSession,
    ContainerAttachError,
    ContainerAttachFrameType,
    ContainerAttachSessionState,
    read_container_attach_request,
    read_secret_chunks,
)
from omninode_rsd.lifecycle.infisical_disposable import (
    ContainerAttachClaimV1,
    ContainerAttachReadyV1,
    ContainerAttachRequestV1,
    ContainerAttachTerminalAckV1,
    ContainerBootstrapAttachProtocolV1,
    ContainerSecretSinkV1,
    TargetDeliveryFieldV1,
    TargetDeliveryValueKindV1,
    container_attach_chunk_descriptors_sha256,
    container_attach_request_sha256,
    container_bootstrap_attach_protocol_sha256,
)

_OPERATION_ID = "11111111-1111-4111-8111-111111111111"
_OTHER_OPERATION_ID = "22222222-2222-4222-8222-222222222222"
_CONTAINER_ID = "a" * 64
_HEADER = struct.Struct("!4sBBI")


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _metadata(model: object) -> bytes:
    return json.dumps(
        cast(object, model).model_dump(mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _frame(frame_type: ContainerAttachFrameType, payload: bytes) -> bytes:
    return _HEADER.pack(b"ONCA", 1, int(frame_type), len(payload)) + payload


def _protocol() -> ContainerBootstrapAttachProtocolV1:
    return ContainerBootstrapAttachProtocolV1(
        schema_version="rsd.container-bootstrap-attach-protocol.v1",
        protocol_name="rsd_container_bootstrap_attach_v1",
        frame_magic="ONCA",
        frame_version=1,
        metadata_encoding="canonical_json_utf8_v1",
        allowed_operation_scopes=("materialize_and_start_runtime_v1", "start_runtime_v2"),
        ready_state="ready_v1",
        claim_state="claimed_v1",
        terminal_ack_state="terminal_ack_v1",
        ambiguous_state="attach_ambiguous_v1",
        max_metadata_bytes=4096,
        max_chunk_bytes=128,
        max_chunks_per_target=4,
        max_total_secret_bytes=256,
        ready_timeout_seconds=10,
        claim_timeout_seconds=10,
        terminal_ack_timeout_seconds=10,
        eof_required_after_terminal_ack=True,
        chunk_order_required=True,
        replay_allowed=False,
        auto_retry_after_secret_delivery_allowed=False,
        secret_persistence_allowed=False,
        secret_logging_allowed=False,
        secret_receipt_allowed=False,
        created_at="2026-08-28T12:00:00Z",
        signer_key_id="attach-signer",
        signature_base64=base64.b64encode(b"p" * 64).decode("ascii"),
    )


def _field(
    ordinal: int,
    *,
    purpose: str,
    target_field: str,
    byte_count: int,
) -> TargetDeliveryFieldV1:
    return TargetDeliveryFieldV1(
        ordinal=ordinal,
        source_purpose=purpose,
        source_reference_sha256=_hash(f"reference-{purpose}"),
        source_fingerprint_sha256=_hash(f"fingerprint-{purpose}"),
        value_kind=TargetDeliveryValueKindV1.DIRECT_PROVIDER_MATERIAL,
        target_field=target_field,
        format=(
            "infisical_hex_16_v1"
            if purpose == "encryption_key"
            else "infisical_auth_secret_base64_32_v1"
        ),
        encoded_byte_count=byte_count,
        sink=ContainerSecretSinkV1.INFISICAL_TARGET_PROCESS_ENVIRONMENT,
        derivation_binding_sha256=_hash(f"fingerprint-{purpose}"),
        persistence_allowed=False,
        logging_allowed=False,
        receipt_allowed=False,
    )


def _request(protocol: ContainerBootstrapAttachProtocolV1) -> ContainerAttachRequestV1:
    return ContainerAttachRequestV1(
        schema_version="rsd.container-attach-request.v1",
        operation_scope="materialize_and_start_runtime_v1",
        operation_id=_OPERATION_ID,
        component="primary_infisical",
        container_id=_CONTAINER_ID,
        derived_image_policy_sha256=_hash("derived-image"),
        wrapper_manifest_sha256=_hash("wrapper-manifest"),
        wrapper_artifact_binding_sha256=_hash("wrapper-binding"),
        attach_protocol_sha256=container_bootstrap_attach_protocol_sha256(protocol),
        target_delivery_map_sha256=_hash("delivery-map"),
        request_nonce_sha256=_hash("nonce"),
        channel_binding_sha256=_hash("channel"),
        session_binding_sha256=_hash("session"),
        expected_ready_state="ready_v1",
        expected_claim_state="claimed_v1",
        expected_terminal_ack_state="terminal_ack_v1",
        fields=(
            _field(
                1,
                purpose="encryption_key",
                target_field="ENCRYPTION_KEY",
                byte_count=32,
            ),
            _field(
                2,
                purpose="auth_secret",
                target_field="AUTH_SECRET",
                byte_count=44,
            ),
        ),
    )


def _ready(request: ContainerAttachRequestV1) -> ContainerAttachReadyV1:
    return ContainerAttachReadyV1(
        schema_version="rsd.container-attach-ready.v1",
        request_sha256=container_attach_request_sha256(request),
        component=request.component,
        container_id=request.container_id,
        state="ready_v1",
        wrapper_artifact_binding_sha256=request.wrapper_artifact_binding_sha256,
        attach_protocol_sha256=request.attach_protocol_sha256,
    )


def _claim(request: ContainerAttachRequestV1) -> ContainerAttachClaimV1:
    return ContainerAttachClaimV1(
        schema_version="rsd.container-attach-claim.v1",
        request_sha256=container_attach_request_sha256(request),
        state="claimed_v1",
        chunk_count=len(request.fields),
        chunk_descriptors_sha256=container_attach_chunk_descriptors_sha256(request.fields),
        eof_required_after_terminal_ack=True,
    )


def _ack(request: ContainerAttachRequestV1) -> ContainerAttachTerminalAckV1:
    claim = _claim(request)
    return ContainerAttachTerminalAckV1(
        schema_version="rsd.container-attach-terminal-ack.v1",
        request_sha256=claim.request_sha256,
        state="terminal_ack_v1",
        chunk_count=claim.chunk_count,
        chunk_descriptors_sha256=claim.chunk_descriptors_sha256,
        chunks_zeroized=True,
        persistence_allowed=False,
        logging_allowed=False,
        receipt_contains_secret=False,
        eof_observed=True,
    )


def _claimed_session() -> tuple[
    ContainerAttachDaemonSession,
    ContainerBootstrapAttachProtocolV1,
    ContainerAttachRequestV1,
]:
    protocol = _protocol()
    request = _request(protocol)
    session = ContainerAttachDaemonSession(protocol=protocol, request=request)
    session.write_request(io.BytesIO())
    session.read_ready(
        io.BytesIO(_frame(ContainerAttachFrameType.READY, _metadata(_ready(request))))
    )
    session.write_claim(io.BytesIO())
    return session, protocol, request


class _Sink:
    def __init__(self) -> None:
        self.received: list[tuple[str, bytes]] = []

    def accept(self, descriptor: TargetDeliveryFieldV1, value: memoryview) -> None:
        self.received.append((descriptor.target_field, bytes(value)))


class _FailingWriter:
    def __init__(self, sentinel: str) -> None:
        self._sentinel = sentinel
        self.calls = 0

    def write(self, data: bytes | bytearray | memoryview) -> int:
        del data
        self.calls += 1
        if self.calls == 3:
            raise RuntimeError(self._sentinel)
        return 0


def _secret_frame(ordinal: int, value: bytes) -> bytes:
    payload = struct.pack("!H", ordinal) + value
    return _frame(ContainerAttachFrameType.SECRET_CHUNK, payload)


def test_attach_round_trip_binds_metadata_consumes_ordered_chunks_and_zeroizes() -> None:
    protocol = _protocol()
    request = _request(protocol)
    session = ContainerAttachDaemonSession(protocol=protocol, request=request)
    request_wire = io.BytesIO()
    session.write_request(request_wire)

    assert (
        read_container_attach_request(
            io.BytesIO(request_wire.getvalue()),
            protocol=protocol,
            expected_request=request,
        )
        == request
    )
    session.read_ready(
        io.BytesIO(_frame(ContainerAttachFrameType.READY, _metadata(_ready(request))))
    )
    claim = session.write_claim(io.BytesIO())
    first = bytearray(b"one-attach-sentinel" + b"x" * 13)
    second = bytearray(b"two-attach-sentinel" + b"y" * 25)
    assert len(first) == 32
    assert len(second) == 44
    secret_wire = io.BytesIO()
    session.write_secret_chunks(secret_wire, (first, second))
    assert first == bytearray(32)
    assert second == bytearray(44)

    delivery = read_secret_chunks(
        io.BytesIO(secret_wire.getvalue()),
        protocol=protocol,
        request=request,
        claim=claim,
    )
    sink = _Sink()
    delivery.consume_into(sink)
    assert sink.received == [
        ("ENCRYPTION_KEY", b"one-attach-sentinel" + b"x" * 13),
        ("AUTH_SECRET", b"two-attach-sentinel" + b"y" * 25),
    ]
    assert all(buffer == bytearray(len(buffer)) for buffer in delivery._buffers)

    session.read_terminal_ack(
        io.BytesIO(_frame(ContainerAttachFrameType.TERMINAL_ACK, _metadata(_ack(request))))
    )
    session.require_eof(io.BytesIO())
    assert session.state is ContainerAttachSessionState.CLOSED


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("operation_id", _OTHER_OPERATION_ID),
        ("component", "restore_infisical"),
        ("derived_image_policy_sha256", _hash("substituted-image")),
        ("wrapper_artifact_binding_sha256", _hash("substituted-wrapper")),
        ("request_nonce_sha256", _hash("substituted-nonce")),
    ),
)
def test_wrapper_rejects_substituted_request_bindings_before_ready(
    field: str, replacement: str
) -> None:
    protocol = _protocol()
    expected = _request(protocol)
    substituted = expected.model_copy(update={field: replacement})
    sender = ContainerAttachDaemonSession(protocol=protocol, request=substituted)
    wire = io.BytesIO()
    sender.write_request(wire)

    with pytest.raises(ContainerAttachError, match="attach_request"):
        read_container_attach_request(
            io.BytesIO(wire.getvalue()), protocol=protocol, expected_request=expected
        )


def test_wrapper_rejects_field_order_swap_before_any_chunk() -> None:
    protocol = _protocol()
    expected = _request(protocol)
    first, second = expected.fields
    swapped = expected.model_copy(
        update={
            "fields": (
                second.model_copy(update={"ordinal": 1}),
                first.model_copy(update={"ordinal": 2}),
            )
        }
    )
    sender = ContainerAttachDaemonSession(protocol=protocol, request=swapped)
    wire = io.BytesIO()
    sender.write_request(wire)

    with pytest.raises(ContainerAttachError, match="attach_request"):
        read_container_attach_request(
            io.BytesIO(wire.getvalue()), protocol=protocol, expected_request=expected
        )


def test_attach_rejects_oversized_truncated_and_unknown_frames() -> None:
    protocol = _protocol()
    request = _request(protocol)
    oversized = _HEADER.pack(
        b"ONCA", 1, int(ContainerAttachFrameType.REQUEST), protocol.max_metadata_bytes + 1
    )
    with pytest.raises(ContainerAttachError, match="frame_header"):
        read_container_attach_request(
            io.BytesIO(oversized), protocol=protocol, expected_request=request
        )

    session = ContainerAttachDaemonSession(protocol=protocol, request=request)
    request_wire = io.BytesIO()
    session.write_request(request_wire)
    with pytest.raises(ContainerAttachError, match="frame_payload"):
        read_container_attach_request(
            io.BytesIO(request_wire.getvalue()[:-1]), protocol=protocol, expected_request=request
        )

    with pytest.raises(ContainerAttachError, match="frame_header"):
        session.read_ready(io.BytesIO(_HEADER.pack(b"ONCA", 1, 99, 0)))


def test_attach_rejects_repeated_or_out_of_order_claim_and_ack() -> None:
    protocol = _protocol()
    request = _request(protocol)
    session = ContainerAttachDaemonSession(protocol=protocol, request=request)
    session.write_request(io.BytesIO())
    with pytest.raises(ContainerAttachError, match="frame_header"):
        session.read_ready(
            io.BytesIO(_frame(ContainerAttachFrameType.CLAIM, _metadata(_claim(request))))
        )

    session, _, request = _claimed_session()
    with pytest.raises(ContainerAttachError, match="state"):
        session.write_claim(io.BytesIO())
    with pytest.raises(ContainerAttachError, match="state"):
        session.read_terminal_ack(
            io.BytesIO(_frame(ContainerAttachFrameType.TERMINAL_ACK, _metadata(_ack(request))))
        )


def test_attach_rejects_secret_chunk_reordering_by_wire_ordinal() -> None:
    protocol = _protocol()
    request = _request(protocol)
    claim = _claim(request)
    reordered = _secret_frame(2, b"b" * 44) + _secret_frame(1, b"a" * 32)

    with pytest.raises(ContainerAttachError, match="secret_chunk"):
        read_secret_chunks(io.BytesIO(reordered), protocol=protocol, request=request, claim=claim)


def test_attach_terminal_ack_failure_or_trailing_data_is_ambiguous() -> None:
    session, _, request = _claimed_session()
    first = bytearray(b"a" * 32)
    second = bytearray(b"b" * 44)
    session.write_secret_chunks(io.BytesIO(), (first, second))
    bad_ack = _ack(request).model_copy(update={"chunk_count": 1})

    with pytest.raises(ContainerAttachError, match="terminal_ack"):
        session.read_terminal_ack(
            io.BytesIO(_frame(ContainerAttachFrameType.TERMINAL_ACK, _metadata(bad_ack)))
        )
    assert session.state is ContainerAttachSessionState.AMBIGUOUS
    with pytest.raises(ContainerAttachError, match="state"):
        session.write_secret_chunks(io.BytesIO(), (bytearray(b"a" * 32), bytearray(b"b" * 44)))

    session, _, request = _claimed_session()
    session.write_secret_chunks(io.BytesIO(), (bytearray(b"a" * 32), bytearray(b"b" * 44)))
    session.read_terminal_ack(
        io.BytesIO(_frame(ContainerAttachFrameType.TERMINAL_ACK, _metadata(_ack(request))))
    )
    with pytest.raises(ContainerAttachError, match="trailing_data"):
        session.require_eof(io.BytesIO(b"x"))
    assert session.state is ContainerAttachSessionState.AMBIGUOUS


def test_attach_rejects_invalid_timeout_type_drift_before_io() -> None:
    protocol = _protocol().model_copy(update={"ready_timeout_seconds": 0})
    with pytest.raises(ContainerAttachError, match="attach_protocol"):
        ContainerAttachDaemonSession(protocol=protocol, request=_request(_protocol()))


def test_attach_secret_sentinel_never_enters_metadata_errors_or_receipt_state() -> None:
    sentinel = "container-attach-secret-sentinel"
    session, protocol, request = _claimed_session()
    metadata = _metadata(request) + _metadata(_claim(request)) + _metadata(_ack(request))
    assert sentinel.encode("ascii") not in metadata
    value = bytearray((sentinel.encode("ascii") + b"x" * 32)[:32])
    other = bytearray(b"b" * 44)

    with pytest.raises(ContainerAttachError) as raised:
        session.write_secret_chunks(_FailingWriter(sentinel), (value, other))
    error = raised.value
    assert sentinel not in str(error)
    assert sentinel not in repr(error)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert value == bytearray(32)
    assert other == bytearray(44)
    assert session.state is ContainerAttachSessionState.AMBIGUOUS

    claim = _claim(request)
    delivery = read_secret_chunks(
        io.BytesIO(_secret_frame(1, b"a" * 32) + _secret_frame(2, b"b" * 44)),
        protocol=protocol,
        request=request,
        claim=claim,
    )

    class SinkFailure:
        def accept(self, descriptor: TargetDeliveryFieldV1, value: memoryview) -> None:
            del descriptor, value
            raise RuntimeError(sentinel)

    with pytest.raises(ContainerAttachError) as sink_raised:
        delivery.consume_into(SinkFailure())
    assert sentinel not in str(sink_raised.value)
    assert sink_raised.value.__cause__ is None
    assert sink_raised.value.__context__ is None
    assert sentinel not in repr(delivery)
    assert all(buffer == bytearray(len(buffer)) for buffer in delivery._buffers)


def test_attach_protocol_model_rejects_zero_timeout() -> None:
    with pytest.raises(ValidationError):
        ContainerBootstrapAttachProtocolV1.model_validate(
            _protocol().model_dump(mode="python") | {"terminal_ack_timeout_seconds": 0}
        )
