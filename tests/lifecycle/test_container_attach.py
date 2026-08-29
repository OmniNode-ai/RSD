"""Adversarial tests for deadline-bound, one-shot local attach framing.

All channels are in-memory fakes.  They prove the public-safe contract without
opening an attach socket, Docker engine, provider, database, or network endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import threading
import traceback
from dataclasses import dataclass, field
from typing import cast

import pytest
from pydantic import ValidationError

from omninode_rsd.lifecycle.container_attach import (
    ContainerAttachDaemonSession,
    ContainerAttachError,
    ContainerAttachFrameType,
    ContainerAttachNonceAuthority,
    ContainerAttachNonceClaimResult,
    ContainerAttachNonceClaimV1,
    ContainerAttachSessionState,
    consume_container_attach_secret_chunks,
    read_container_attach_request,
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


@dataclass(slots=True)
class _Clock:
    now: float = 100.0

    def monotonic(self) -> float:
        return self.now


@dataclass(slots=True)
class _Channel:
    """A deadline-capable byte channel with controlled partial/failure behavior."""

    clock: _Clock
    incoming: bytearray = field(default_factory=bytearray)
    outgoing: bytearray = field(default_factory=bytearray)
    read_limit: int | None = None
    write_limit: int | None = None
    advance_on_read: float = 0.0
    advance_on_write: float = 0.0
    fail_write_call: int | None = None
    none_write_call: int | None = None
    sentinel: str | None = None
    write_calls: int = 0

    def read(self, count: int, *, deadline: float) -> bytes:
        if self.clock.now >= deadline:
            raise TimeoutError("deadline")
        self.clock.now += self.advance_on_read
        if self.clock.now >= deadline:
            raise TimeoutError("deadline")
        if not self.incoming:
            return b""
        limit = count if self.read_limit is None else min(count, self.read_limit)
        value = bytes(self.incoming[:limit])
        del self.incoming[:limit]
        return value

    def write(self, data: bytes | bytearray | memoryview, *, deadline: float) -> int:
        if self.clock.now >= deadline:
            raise TimeoutError("deadline")
        self.write_calls += 1
        if self.fail_write_call == self.write_calls:
            raise RuntimeError(self.sentinel or "writer failure")
        self.clock.now += self.advance_on_write
        if self.clock.now >= deadline:
            raise TimeoutError("deadline")
        rendered = bytes(data)
        if self.none_write_call == self.write_calls:
            self.outgoing.extend(rendered)
            return cast(int, None)
        if self.write_limit is not None and self.write_limit < len(rendered):
            self.outgoing.extend(rendered[: self.write_limit])
            return self.write_limit
        self.outgoing.extend(rendered)
        return len(rendered)


class _NonceAuthority(ContainerAttachNonceAuthority):
    def __init__(self) -> None:
        self._claims: set[tuple[str, str, str, str, str, str]] = set()
        self._lock = threading.Lock()
        self.claims: list[ContainerAttachNonceClaimV1] = []
        self.unavailable = False

    def claim_once(self, claim: ContainerAttachNonceClaimV1) -> ContainerAttachNonceClaimResult:
        key = (
            claim.boundary,
            claim.request_sha256,
            claim.operation_id,
            claim.component,
            claim.request_nonce_sha256,
            claim.target_delivery_map_sha256,
        )
        with self._lock:
            self.claims.append(claim)
            if self.unavailable:
                return ContainerAttachNonceClaimResult.UNAVAILABLE
            if key in self._claims:
                return ContainerAttachNonceClaimResult.REPLAYED
            self._claims.add(key)
            return ContainerAttachNonceClaimResult.CLAIMED


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
    ordinal: int, *, purpose: str, target_field: str, byte_count: int
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
            _field(1, purpose="encryption_key", target_field="ENCRYPTION_KEY", byte_count=32),
            _field(2, purpose="auth_secret", target_field="AUTH_SECRET", byte_count=44),
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


def _session(
    protocol: ContainerBootstrapAttachProtocolV1,
    request: ContainerAttachRequestV1,
    clock: _Clock,
    authority: _NonceAuthority | None = None,
) -> ContainerAttachDaemonSession:
    return ContainerAttachDaemonSession(
        protocol=protocol,
        request=request,
        deadline_clock=clock,
        nonce_authority=authority or _NonceAuthority(),
    )


def _claimed_session() -> tuple[
    ContainerAttachDaemonSession,
    ContainerBootstrapAttachProtocolV1,
    ContainerAttachRequestV1,
    _Clock,
]:
    protocol = _protocol()
    request = _request(protocol)
    clock = _Clock()
    session = _session(protocol, request, clock)
    session.write_request(_Channel(clock))
    session.read_ready(
        _Channel(
            clock, bytearray(_frame(ContainerAttachFrameType.READY, _metadata(_ready(request))))
        )
    )
    session.write_claim(_Channel(clock))
    return session, protocol, request, clock


class _Sink:
    def __init__(self) -> None:
        self.received: list[tuple[str, bytes]] = []

    def accept(self, descriptor: TargetDeliveryFieldV1, value: memoryview) -> None:
        self.received.append((descriptor.target_field, bytes(value)))


def _secret_frame(ordinal: int, value: bytes) -> bytes:
    return _frame(ContainerAttachFrameType.SECRET_CHUNK, struct.pack("!H", ordinal) + value)


def test_attach_round_trip_binds_metadata_consumes_ordered_chunks_and_zeroizes() -> None:
    protocol = _protocol()
    request = _request(protocol)
    clock = _Clock()
    sender_authority = _NonceAuthority()
    session = _session(protocol, request, clock, sender_authority)
    request_wire = _Channel(clock)
    session.write_request(request_wire)

    assert (
        read_container_attach_request(
            _Channel(clock, bytearray(request_wire.outgoing)),
            protocol=protocol,
            expected_request=request,
            deadline_clock=clock,
        )
        == request
    )
    session.read_ready(
        _Channel(
            clock, bytearray(_frame(ContainerAttachFrameType.READY, _metadata(_ready(request))))
        )
    )
    claim = session.write_claim(_Channel(clock))
    first = bytearray(b"one-attach-sentinel" + b"x" * 13)
    second = bytearray(b"two-attach-sentinel" + b"y" * 25)
    secret_wire = _Channel(clock)
    session.write_secret_chunks(secret_wire, (first, second))
    assert first == bytearray(32)
    assert second == bytearray(44)

    sink = _Sink()
    consume_container_attach_secret_chunks(
        _Channel(clock, bytearray(secret_wire.outgoing)),
        protocol=protocol,
        request=request,
        claim=claim,
        sink=sink,
        deadline_clock=clock,
        nonce_authority=_NonceAuthority(),
    )
    assert sink.received == [
        ("ENCRYPTION_KEY", b"one-attach-sentinel" + b"x" * 13),
        ("AUTH_SECRET", b"two-attach-sentinel" + b"y" * 25),
    ]
    session.read_terminal_ack(
        _Channel(
            clock,
            bytearray(_frame(ContainerAttachFrameType.TERMINAL_ACK, _metadata(_ack(request)))),
        )
    )
    session.require_eof(_Channel(clock))
    assert session.state is ContainerAttachSessionState.CLOSED
    assert sender_authority.claims[0].boundary == "daemon_send_v1"


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
    clock = _Clock()
    substituted = expected.model_copy(update={field: replacement})
    sender = _session(protocol, substituted, clock)
    wire = _Channel(clock)
    sender.write_request(wire)

    with pytest.raises(ContainerAttachError, match="attach_request"):
        read_container_attach_request(
            _Channel(clock, bytearray(wire.outgoing)),
            protocol=protocol,
            expected_request=expected,
            deadline_clock=clock,
        )


def test_wrapper_rejects_field_order_swap_before_any_chunk() -> None:
    protocol = _protocol()
    expected = _request(protocol)
    first, second = expected.fields
    clock = _Clock()
    swapped = expected.model_copy(
        update={
            "fields": (
                second.model_copy(update={"ordinal": 1}),
                first.model_copy(update={"ordinal": 2}),
            )
        }
    )
    sender = _session(protocol, swapped, clock)
    wire = _Channel(clock)
    sender.write_request(wire)

    with pytest.raises(ContainerAttachError, match="attach_request"):
        read_container_attach_request(
            _Channel(clock, bytearray(wire.outgoing)),
            protocol=protocol,
            expected_request=expected,
            deadline_clock=clock,
        )


def test_attach_rejects_oversized_truncated_unknown_and_generic_blocking_streams() -> None:
    protocol = _protocol()
    request = _request(protocol)
    clock = _Clock()
    oversized = _HEADER.pack(
        b"ONCA", 1, int(ContainerAttachFrameType.REQUEST), protocol.max_metadata_bytes + 1
    )
    with pytest.raises(ContainerAttachError, match="frame_header"):
        read_container_attach_request(
            _Channel(clock, bytearray(oversized)),
            protocol=protocol,
            expected_request=request,
            deadline_clock=clock,
        )

    session = _session(protocol, request, clock)
    request_wire = _Channel(clock)
    session.write_request(request_wire)
    with pytest.raises(ContainerAttachError, match="frame_payload"):
        read_container_attach_request(
            _Channel(clock, bytearray(request_wire.outgoing[:-1])),
            protocol=protocol,
            expected_request=request,
            deadline_clock=clock,
        )
    with pytest.raises(ContainerAttachError, match="frame_header"):
        session.read_ready(_Channel(clock, bytearray(_HEADER.pack(b"ONCA", 1, 99, 0))))

    class BlockingBinaryIo:
        def read(self, count: int) -> bytes:
            del count
            return b""

    with pytest.raises(ContainerAttachError, match="frame_header"):
        read_container_attach_request(
            BlockingBinaryIo(),  # type: ignore[arg-type]
            protocol=protocol,
            expected_request=request,
            deadline_clock=clock,
        )


def test_attach_rejects_repeated_or_out_of_order_claim_and_ack() -> None:
    protocol = _protocol()
    request = _request(protocol)
    clock = _Clock()
    session = _session(protocol, request, clock)
    session.write_request(_Channel(clock))
    with pytest.raises(ContainerAttachError, match="frame_header"):
        session.read_ready(
            _Channel(
                clock,
                bytearray(_frame(ContainerAttachFrameType.CLAIM, _metadata(_claim(request)))),
            )
        )

    session, _, request, clock = _claimed_session()
    with pytest.raises(ContainerAttachError, match="state"):
        session.write_claim(_Channel(clock))
    with pytest.raises(ContainerAttachError, match="state"):
        session.read_terminal_ack(
            _Channel(
                clock,
                bytearray(_frame(ContainerAttachFrameType.TERMINAL_ACK, _metadata(_ack(request)))),
            )
        )


def test_attach_rejects_secret_chunk_reordering_and_local_receiver_replay() -> None:
    protocol = _protocol()
    request = _request(protocol)
    claim = _claim(request)
    clock = _Clock()
    reordered = _secret_frame(2, b"b" * 44) + _secret_frame(1, b"a" * 32)
    authority = _NonceAuthority()
    with pytest.raises(ContainerAttachError, match="secret_chunk"):
        consume_container_attach_secret_chunks(
            _Channel(clock, bytearray(reordered)),
            protocol=protocol,
            request=request,
            claim=claim,
            sink=_Sink(),
            deadline_clock=clock,
            nonce_authority=authority,
        )

    valid = _secret_frame(1, b"a" * 32) + _secret_frame(2, b"b" * 44)
    with pytest.raises(ContainerAttachError, match="replay"):
        consume_container_attach_secret_chunks(
            _Channel(clock, bytearray(valid)),
            protocol=protocol,
            request=request,
            claim=claim,
            sink=_Sink(),
            deadline_clock=clock,
            nonce_authority=authority,
        )


def test_attach_sender_replay_is_claimed_before_secret_frames_and_buffers_zeroize() -> None:
    protocol = _protocol()
    request = _request(protocol)
    clock = _Clock()
    authority = _NonceAuthority()
    first, second = bytearray(b"a" * 32), bytearray(b"b" * 44)
    session = _session(protocol, request, clock, authority)
    session.write_request(_Channel(clock))
    session.read_ready(
        _Channel(
            clock, bytearray(_frame(ContainerAttachFrameType.READY, _metadata(_ready(request))))
        )
    )
    session.write_claim(_Channel(clock))
    session.write_secret_chunks(_Channel(clock), (first, second))

    replay_first, replay_second = bytearray(b"a" * 32), bytearray(b"b" * 44)
    replay = _session(protocol, request, clock, authority)
    replay.write_request(_Channel(clock))
    replay.read_ready(
        _Channel(
            clock, bytearray(_frame(ContainerAttachFrameType.READY, _metadata(_ready(request))))
        )
    )
    replay.write_claim(_Channel(clock))
    writer = _Channel(clock)
    with pytest.raises(ContainerAttachError, match="replay"):
        replay.write_secret_chunks(writer, (replay_first, replay_second))
    assert writer.outgoing == b""
    assert replay_first == bytearray(32)
    assert replay_second == bytearray(44)


@pytest.mark.parametrize("fail_write_call", (None, 1))
def test_attach_rejects_list_buffers_before_any_claim_or_secret_handling(
    fail_write_call: int | None,
) -> None:
    """Lists are rejected equally before a would-be success or writer failure."""

    session, _, _, clock = _claimed_session()
    first, second = bytearray(b"a" * 32), bytearray(b"b" * 44)
    list_chunks = [first, second]
    writer = _Channel(clock, fail_write_call=fail_write_call)
    with pytest.raises(ContainerAttachError, match="secret_chunks"):
        session.write_secret_chunks(writer, list_chunks)  # type: ignore[arg-type]
    assert writer.outgoing == b""
    assert first == bytearray(b"a" * 32)
    assert second == bytearray(b"b" * 44)


def test_attach_tuple_buffers_zeroize_on_writer_failure_without_secret_context() -> None:
    sentinel = "container-attach-secret-sentinel"
    session, _, _, clock = _claimed_session()
    first, second = bytearray(b"a" * 32), bytearray(b"b" * 44)
    writer = _Channel(clock, fail_write_call=3, sentinel=sentinel)
    with pytest.raises(ContainerAttachError) as raised:
        session.write_secret_chunks(writer, (first, second))
    _assert_redacted(raised.value, sentinel)
    assert first == bytearray(32)
    assert second == bytearray(44)
    assert session.state is ContainerAttachSessionState.AMBIGUOUS


def test_attach_rejects_unknown_write_result_and_zeroizes_buffers() -> None:
    """A writer must prove a complete write rather than return ``None``."""

    session, _, _, clock = _claimed_session()
    first, second = bytearray(b"a" * 32), bytearray(b"b" * 44)
    writer = _Channel(clock, none_write_call=1)
    with pytest.raises(ContainerAttachError, match="frame_write"):
        session.write_secret_chunks(writer, (first, second))
    assert first == bytearray(32)
    assert second == bytearray(44)
    assert session.state is ContainerAttachSessionState.AMBIGUOUS


def test_attach_timeout_partial_no_progress_and_ack_failure_are_fail_closed() -> None:
    session, _, request, clock = _claimed_session()
    first, second = bytearray(b"a" * 32), bytearray(b"b" * 44)
    session.write_secret_chunks(_Channel(clock), (first, second))
    slow = _Channel(
        clock,
        bytearray(_frame(ContainerAttachFrameType.TERMINAL_ACK, _metadata(_ack(request)))),
        read_limit=1,
        advance_on_read=11.0,
    )
    with pytest.raises(ContainerAttachError, match="frame_header"):
        session.read_terminal_ack(slow)
    assert session.state is ContainerAttachSessionState.AMBIGUOUS

    session, _, request, clock = _claimed_session()
    session.write_secret_chunks(_Channel(clock), (bytearray(b"a" * 32), bytearray(b"b" * 44)))
    session.read_terminal_ack(
        _Channel(
            clock,
            bytearray(_frame(ContainerAttachFrameType.TERMINAL_ACK, _metadata(_ack(request)))),
        )
    )
    with pytest.raises(ContainerAttachError, match="trailing_data"):
        session.require_eof(_Channel(clock, bytearray(b"x")))
    assert session.state is ContainerAttachSessionState.AMBIGUOUS


def _assert_redacted(error: BaseException, sentinel: str) -> None:
    assert sentinel not in str(error)
    assert sentinel not in repr(error)
    assert sentinel not in repr(error.__dict__)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert all(sentinel not in line for line in traceback.format_exception(error))
    assert all(sentinel not in str(note) for note in getattr(error, "__notes__", ()))


def test_attach_metadata_and_sink_failures_have_no_secret_error_chain() -> None:
    protocol = _protocol()
    request = _request(protocol)
    clock = _Clock()
    sentinel = "container-attach-secret-sentinel"
    invalid = request.model_copy(update={"container_id": sentinel})
    with pytest.raises(ContainerAttachError) as raised:
        read_container_attach_request(
            _Channel(
                clock, bytearray(_frame(ContainerAttachFrameType.REQUEST, _metadata(invalid)))
            ),
            protocol=protocol,
            expected_request=request,
            deadline_clock=clock,
        )
    _assert_redacted(raised.value, sentinel)

    class FailingSink:
        def accept(self, descriptor: TargetDeliveryFieldV1, value: memoryview) -> None:
            del descriptor, value
            raise RuntimeError(sentinel)

    with pytest.raises(ContainerAttachError) as sink_raised:
        consume_container_attach_secret_chunks(
            _Channel(
                clock,
                bytearray(_secret_frame(1, b"a" * 32) + _secret_frame(2, b"b" * 44)),
            ),
            protocol=protocol,
            request=request,
            claim=_claim(request),
            sink=FailingSink(),
            deadline_clock=clock,
            nonce_authority=_NonceAuthority(),
        )
    _assert_redacted(sink_raised.value, sentinel)


def test_attach_nonce_authority_failure_blocks_before_secret_read_and_concurrent_claims() -> None:
    protocol = _protocol()
    request = _request(protocol)
    claim = _claim(request)
    clock = _Clock()
    unavailable = _NonceAuthority()
    unavailable.unavailable = True
    wire = _Channel(clock, bytearray(_secret_frame(1, b"a" * 32) + _secret_frame(2, b"b" * 44)))
    with pytest.raises(ContainerAttachError, match="nonce_authority"):
        consume_container_attach_secret_chunks(
            wire,
            protocol=protocol,
            request=request,
            claim=claim,
            sink=_Sink(),
            deadline_clock=clock,
            nonce_authority=unavailable,
        )
    assert wire.incoming

    authority = _NonceAuthority()
    outcomes: list[str] = []
    lock = threading.Lock()

    def consume() -> None:
        try:
            consume_container_attach_secret_chunks(
                _Channel(
                    clock,
                    bytearray(_secret_frame(1, b"a" * 32) + _secret_frame(2, b"b" * 44)),
                ),
                protocol=protocol,
                request=request,
                claim=claim,
                sink=_Sink(),
                deadline_clock=clock,
                nonce_authority=authority,
            )
            result = "claimed"
        except ContainerAttachError as error:
            result = error.phase
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=consume) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["claimed", "replay"]


def test_attach_protocol_model_rejects_zero_timeout_and_type_drift_before_io() -> None:
    with pytest.raises(ValidationError):
        ContainerBootstrapAttachProtocolV1.model_validate(
            _protocol().model_dump(mode="python") | {"terminal_ack_timeout_seconds": 0}
        )
    protocol = _protocol().model_copy(update={"ready_timeout_seconds": 0})
    with pytest.raises(ContainerAttachError, match="attach_protocol"):
        _session(protocol, _request(_protocol()), _Clock())
