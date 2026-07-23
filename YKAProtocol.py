from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
import re
from typing import Sequence

from YKACompatibility import CompatibilityProfile, load_compatibility_profile


MAX_TCP_SPAN = 64 * 1024 * 1024
MAX_MPPC_OUTPUT = 64 * 1024 * 1024
MAX_FRAME_SIZE = 64 * 1024 * 1024


class ProtocolDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class TcpSegment:
    stream_id: int
    sequence: int
    payload: bytes
    capture_order: int = 0


@dataclass(frozen=True)
class TcpSegmentSpan:
    start: int
    end: int
    capture_order: int


@dataclass(frozen=True)
class TcpReassembly:
    stream_id: int
    sequence_start: int
    payload: bytes
    segment_count: int
    gap_bytes: int
    conflict_bytes: int
    server_port: int | None = None
    locator: str | None = None
    segment_spans: tuple[TcpSegmentSpan, ...] = ()


@dataclass(frozen=True)
class TcpFlowMetadata:
    stream_id: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_syn_seen: bool
    server_syn_seen: bool

    @property
    def handshake_complete(self) -> bool:
        return self.client_syn_seen and self.server_syn_seen


@dataclass
class _FlowState:
    stream_id: int
    connection: tuple[int, str, int, str, int]
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_syn_sequence: int | None = None
    client_syn_seen: bool = False
    server_syn_seen: bool = False
    fin_directions: int = 0

    def metadata(self) -> TcpFlowMetadata:
        return TcpFlowMetadata(
            self.stream_id,
            self.client_ip,
            self.client_port,
            self.server_ip,
            self.server_port,
            self.client_syn_seen,
            self.server_syn_seen,
        )


@dataclass(frozen=True)
class MPPCBlockBoundary:
    compressed_end: int
    decompressed_end: int


@dataclass(frozen=True)
class MPPCResult:
    data: bytes
    block_count: int
    bits_consumed: int
    error: str | None
    block_boundaries: tuple[MPPCBlockBoundary, ...] = ()


@dataclass(frozen=True)
class CompactFrame:
    offset: int
    type_id: int
    declared_length: int
    payload: bytes
    transport: str


@dataclass(frozen=True)
class PartialCompactFrame:
    offset: int
    type_id: int
    declared_length: int
    payload: bytes
    transport: str


@dataclass(frozen=True)
class FrameParseResult:
    frames: tuple[CompactFrame, ...]
    partial: PartialCompactFrame | None
    consumed: int
    error: str | None


@dataclass(frozen=True)
class DecodedServerStream:
    reassembly: TcpReassembly
    transport_mode: str
    plaintext_bytes: int
    compressed_bytes: int
    decompressed_bytes: int
    mppc_blocks: int
    frames: tuple[CompactFrame, ...]
    partial_frame: PartialCompactFrame | None
    decode_error: str | None
    mppc_block_boundaries: tuple[MPPCBlockBoundary, ...] = ()


@dataclass(frozen=True)
class DecodedClientStream:
    reassembly: TcpReassembly
    transport_mode: str
    frames: tuple[CompactFrame, ...]
    partial_frame: PartialCompactFrame | None
    decode_error: str | None


@dataclass(frozen=True)
class GameMessage:
    command_id: int
    payload: bytes
    frame_offset: int
    source: str
    stream_id: int | None = None
    capture_id: str | None = None
    resolution_mode: str = "profile"
    observed_opcode: int | None = None
    observed_wrapper_opcode: int | None = None
    delivery_order: int | None = None


@dataclass(frozen=True)
class ProtobufField:
    number: int
    wire_type: int
    value: int | bytes


@dataclass(frozen=True)
class ProtobufParseResult:
    fields: tuple[ProtobufField, ...]
    complete: bool
    consumed: int
    error: str | None


class _BitReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    @property
    def remaining(self) -> int:
        return len(self.data) * 8 - self.position

    def take(self, count: int) -> int:
        if count < 0 or self.remaining < count:
            raise EOFError("not enough MPPC bits")
        value = 0
        for _ in range(count):
            byte = self.data[self.position >> 3]
            shift = 7 - (self.position & 7)
            value = (value << 1) | ((byte >> shift) & 1)
            self.position += 1
        return value

    def peek(self, count: int) -> int:
        position = self.position
        try:
            return self.take(count)
        finally:
            self.position = position

    def peek_padded(self, count: int) -> int:
        available = min(count, self.remaining)
        return self.peek(available) << (count - available)


def _read_capture_segments(
    pcaps: Sequence[Path],
    profile: CompatibilityProfile | None = None,
) -> tuple[
    list[TcpSegment],
    list[TcpSegment],
    Counter[str],
    dict[int, TcpFlowMetadata],
]:
    try:
        from scapy.layers.inet import IP, TCP, UDP  # type: ignore[import-untyped]
        from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
        from scapy.utils import PcapReader  # type: ignore[import-untyped]
    except ImportError as error:
        raise ProtocolDecodeError("Scapy is required for offline capture analysis") from error

    profile = profile or load_compatibility_profile()
    server_segments: list[TcpSegment] = []
    client_segments: list[TcpSegment] = []
    protocol_counts: Counter[str] = Counter()
    active_streams: dict[tuple[int, str, int, str, int], _FlowState] = {}
    flows: dict[int, _FlowState] = {}
    sequence_anchors: dict[tuple[int, str], int] = {}
    next_stream_id = 0
    capture_order = 0

    for pcap in pcaps:
        try:
            reader = PcapReader(str(pcap))
        except (OSError, ValueError) as error:
            raise ProtocolDecodeError(f"Scapy could not open {pcap.name}: {error}") from error
        try:
            for packet in reader:
                capture_order += 1
                if TCP in packet:
                    protocol_counts["TCP"] += 1
                elif UDP in packet:
                    protocol_counts["UDP"] += 1
                    continue
                else:
                    protocol_counts["Other"] += 1
                    continue

                tcp = packet[TCP]
                source_port = int(tcp.sport)
                destination_port = int(tcp.dport)
                if IP in packet:
                    network = packet[IP]
                    ip_version = 4
                elif IPv6 in packet:
                    network = packet[IPv6]
                    ip_version = 6
                else:
                    continue

                source_ip = str(network.src)
                destination_ip = str(network.dst)
                forward = (
                    ip_version,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                )
                reverse = (
                    ip_version,
                    destination_ip,
                    destination_port,
                    source_ip,
                    source_port,
                )
                flags = int(tcp.flags)
                starts_connection = bool(flags & 0x02) and not bool(flags & 0x10)
                raw_sequence = int(tcp.seq) & 0xFFFFFFFF
                flow = active_streams.get(forward)
                direction = "client"
                if flow is None:
                    flow = active_streams.get(reverse)
                    direction = "server"

                if starts_connection:
                    flow = active_streams.get(forward)
                    if (
                        flow is None
                        or flow.client_syn_sequence != raw_sequence
                        or flow.fin_directions
                    ):
                        flow = _FlowState(
                            stream_id=next_stream_id,
                            connection=forward,
                            client_ip=source_ip,
                            client_port=source_port,
                            server_ip=destination_ip,
                            server_port=destination_port,
                        )
                        next_stream_id += 1
                        active_streams[forward] = flow
                        flows[flow.stream_id] = flow
                    direction = "client"
                    flow.client_syn_sequence = raw_sequence
                    flow.client_syn_seen = True
                elif flow is None:
                    if profile.is_known_service_port(destination_port):
                        direction = "client"
                        connection = forward
                        client_ip = source_ip
                        client_port = source_port
                        server_ip = destination_ip
                        server_port = destination_port
                    elif profile.is_known_service_port(source_port):
                        direction = "server"
                        connection = reverse
                        client_ip = destination_ip
                        client_port = destination_port
                        server_ip = source_ip
                        server_port = source_port
                    else:
                        # An unknown-port flow without its opening SYN cannot be
                        # oriented safely and is deliberately left unclassified.
                        continue
                    flow = _FlowState(
                        stream_id=next_stream_id,
                        connection=connection,
                        client_ip=client_ip,
                        client_port=client_port,
                        server_ip=server_ip,
                        server_port=server_port,
                    )
                    next_stream_id += 1
                    active_streams[connection] = flow
                    flows[flow.stream_id] = flow

                if flow is None:
                    continue
                if flags & 0x02:
                    if direction == "client":
                        flow.client_syn_seen = True
                    else:
                        flow.server_syn_seen = True
                    # Retain SYN+1 as a zero-length anchor so a capture that
                    # starts after the handshake still reports the missing
                    # prefix instead of silently rebasing at first payload.
                    syn_anchor = raw_sequence + 1
                    (server_segments if direction == "server" else client_segments).append(
                        TcpSegment(
                            flow.stream_id,
                            syn_anchor,
                            b"",
                            capture_order,
                        )
                    )

                payload = bytes(tcp.payload)
                if payload:
                    anchor_key = (flow.stream_id, direction)
                    anchor = sequence_anchors.get(anchor_key)
                    if anchor is None:
                        sequence = raw_sequence + (1 if flags & 0x02 else 0)
                    else:
                        base = anchor & ~0xFFFFFFFF
                        candidates = (
                            base + raw_sequence - 0x100000000,
                            base + raw_sequence,
                            base + raw_sequence + 0x100000000,
                        )
                        sequence = min(candidates, key=lambda value: abs(value - anchor))
                    # Keep the highest seen end as the unwrap anchor.  This
                    # handles 32-bit sequence rollover while remaining stable
                    # for retransmissions and mild reordering.
                    sequence_anchors[anchor_key] = max(
                        anchor if anchor is not None else sequence,
                        sequence + len(payload),
                    )
                    segment = TcpSegment(
                        flow.stream_id,
                        sequence,
                        payload,
                        capture_order,
                    )
                    if direction == "server":
                        server_segments.append(segment)
                    else:
                        client_segments.append(segment)
                if flags & 0x04:
                    active_streams.pop(flow.connection, None)
                elif flags & 0x01:
                    direction_bit = 1 if direction == "server" else 2
                    finished = flow.fin_directions | direction_bit
                    if finished == 3:
                        active_streams.pop(flow.connection, None)
                    else:
                        flow.fin_directions = finished
        except (OSError, ValueError) as error:
            raise ProtocolDecodeError(f"Scapy failed while reading {pcap.name}: {error}") from error
        finally:
            reader.close()
    return (
        server_segments,
        client_segments,
        protocol_counts,
        {stream_id: flow.metadata() for stream_id, flow in flows.items()},
    )


def _read_server_segments(pcap: Path) -> list[TcpSegment]:
    profile = load_compatibility_profile()
    server, _client, _counts, flows = _read_capture_segments((pcap,), profile)
    known = {
        stream_id
        for stream_id, flow in flows.items()
        if profile.is_known_service_port(flow.server_port)
    }
    return [segment for segment in server if segment.stream_id in known]


def _read_client_segments(pcap: Path) -> list[TcpSegment]:
    profile = load_compatibility_profile()
    _server, client, _counts, flows = _read_capture_segments((pcap,), profile)
    known = {
        stream_id
        for stream_id, flow in flows.items()
        if profile.is_known_service_port(flow.server_port)
    }
    return [segment for segment in client if segment.stream_id in known]


def reassemble_server_streams(pcap: Path) -> tuple[TcpReassembly, ...]:
    return _reassemble_segments(_read_server_segments(pcap))


def _reassemble_segments(segments: list[TcpSegment]) -> tuple[TcpReassembly, ...]:
    grouped: dict[int, list[TcpSegment]] = defaultdict(list)
    for segment in segments:
        grouped[segment.stream_id].append(segment)
    streams: list[TcpReassembly] = []
    for stream_id, stream_segments in sorted(grouped.items()):
        sequence_start = min(segment.sequence for segment in stream_segments)
        sequence_end = max(
            segment.sequence + len(segment.payload)
            for segment in stream_segments
        )
        span = sequence_end - sequence_start
        if span < 0 or span > MAX_TCP_SPAN:
            raise ProtocolDecodeError(
                f"TCP stream {stream_id} span is outside the limit: {span}"
            )
        payload = bytearray(span)
        covered_bytes = 0
        covered_end = 0
        conflicts = 0
        for segment in sorted(stream_segments, key=lambda item: item.sequence):
            start = segment.sequence - sequence_start
            end = start + len(segment.payload)

            # Segments are sorted by start, so only the prefix before the
            # highest covered end can overlap earlier data.  Compare that
            # prefix without overwriting it, preserving first-writer-wins.
            overlap_length = max(0, min(end, covered_end) - start)
            if overlap_length:
                existing = memoryview(payload)[start : start + overlap_length]
                incoming = memoryview(segment.payload)[:overlap_length]
                if existing != incoming:
                    conflicts += sum(
                        left != right
                        for left, right in zip(existing, incoming)
                    )
                del existing, incoming

            uncovered_start = max(start, covered_end)
            if end > uncovered_start:
                source_start = uncovered_start - start
                payload[uncovered_start:end] = segment.payload[source_start:]
                covered_bytes += end - uncovered_start
                covered_end = end

        streams.append(
            TcpReassembly(
                stream_id=stream_id,
                sequence_start=sequence_start,
                payload=bytes(payload),
                segment_count=len(stream_segments),
                gap_bytes=span - covered_bytes,
                conflict_bytes=conflicts,
                segment_spans=tuple(
                    TcpSegmentSpan(
                        start=segment.sequence - sequence_start,
                        end=(
                            segment.sequence
                            - sequence_start
                            + len(segment.payload)
                        ),
                        capture_order=segment.capture_order,
                    )
                    for segment in sorted(
                        stream_segments,
                        key=lambda item: (
                            item.capture_order,
                            item.sequence,
                        ),
                    )
                    if segment.payload and segment.capture_order > 0
                ),
            )
        )
    return tuple(streams)


def reassemble_client_streams(pcap: Path) -> tuple[TcpReassembly, ...]:
    return _reassemble_segments(_read_client_segments(pcap))


def decompress_mppc(
    data: bytes, *, output_limit: int = MAX_MPPC_OUTPUT
) -> MPPCResult:
    reader = _BitReader(data)
    history = bytearray()
    emitted = 0
    output = bytearray()
    block_count = 0
    block_boundaries: list[MPPCBlockBoundary] = []
    error: str | None = None

    def check_output_limit() -> None:
        pending = len(history) - emitted
        if len(output) + pending > output_limit:
            raise ProtocolDecodeError(
                f"MPPC output exceeds the {output_limit}-byte limit"
            )

    try:
        while reader.remaining:
            if reader.peek(1) == 0:
                history.append(reader.take(8))
                if len(history) > 8192:
                    raise ProtocolDecodeError("MPPC history exceeded 8192 bytes")
                check_output_limit()
                continue
            if reader.peek(2) == 0b10:
                history.append((reader.take(9) & 0x7F) | 0x80)
                if len(history) > 8192:
                    raise ProtocolDecodeError("MPPC history exceeded 8192 bytes")
                check_output_limit()
                continue

            if reader.peek(4) == 0b1111:
                offset = reader.take(10) & 0x3F
                if offset == 0:
                    padding = (-reader.position) % 8
                    if padding:
                        reader.take(padding)
                    output.extend(history[emitted:])
                    block_count += 1
                    block_boundaries.append(
                        MPPCBlockBoundary(
                            compressed_end=reader.position // 8,
                            decompressed_end=len(output),
                        )
                    )
                    if len(history) == 8192:
                        history.clear()
                        emitted = 0
                    else:
                        emitted = len(history)
                    continue
            elif reader.peek(3) == 0b111:
                offset = (reader.take(12) & 0xFF) + 64
            elif reader.peek(2) == 0b11:
                offset = (reader.take(16) & 0x1FFF) + 320
            else:
                raise ProtocolDecodeError("invalid MPPC offset prefix")

            prefix = reader.peek_padded(24)
            if prefix < 0x800000:
                reader.take(1)
                length = 3
            elif prefix < 0xC00000:
                length = 4 | (reader.take(4) & 0x03)
            elif prefix < 0xE00000:
                length = 8 | (reader.take(6) & 0x07)
            elif prefix < 0xF00000:
                length = 16 | (reader.take(8) & 0x0F)
            elif prefix < 0xF80000:
                length = 32 | (reader.take(10) & 0x1F)
            elif prefix < 0xFC0000:
                length = 64 | (reader.take(12) & 0x3F)
            elif prefix < 0xFE0000:
                length = 128 | (reader.take(14) & 0x7F)
            elif prefix < 0xFF0000:
                length = 256 | (reader.take(16) & 0xFF)
            elif prefix < 0xFF8000:
                length = 512 | (reader.take(18) & 0x1FF)
            elif prefix < 0xFFC000:
                length = 1024 | (reader.take(20) & 0x3FF)
            elif prefix < 0xFFE000:
                length = 2048 | (reader.take(22) & 0x7FF)
            elif prefix < 0xFFF000:
                length = 4096 | (reader.take(24) & 0xFFF)
            else:
                raise ProtocolDecodeError("invalid MPPC length prefix")

            if (
                offset <= 0
                or offset > len(history)
                or len(history) + length > 8192
            ):
                raise ProtocolDecodeError(
                    "invalid MPPC history reference "
                    f"(offset={offset}, length={length}, history={len(history)})"
                )
            for _ in range(length):
                history.append(history[-offset])
            check_output_limit()
    except EOFError:
        error = "truncated MPPC symbol"
    except ProtocolDecodeError as decode_error:
        error = str(decode_error)

    output.extend(history[emitted:])
    return MPPCResult(
        data=bytes(output),
        block_count=block_count,
        bits_consumed=reader.position,
        error=error,
        block_boundaries=tuple(block_boundaries),
    )


def read_compact_uint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise EOFError("missing compact uint")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    if first < 0xC0:
        end = offset + 2
        if end > len(data):
            raise EOFError("truncated two-byte compact uint")
        return ((first & 0x3F) << 8) | data[offset + 1], end
    if first < 0xE0:
        end = offset + 4
        if end > len(data):
            raise EOFError("truncated four-byte compact uint")
        return (
            ((first & 0x1F) << 24)
            | (data[offset + 1] << 16)
            | (data[offset + 2] << 8)
            | data[offset + 3],
            end,
        )
    if first == 0xE0:
        end = offset + 5
        if end > len(data):
            raise EOFError("truncated five-byte compact uint")
        return int.from_bytes(data[offset + 1 : end], "big"), end
    raise ProtocolDecodeError(f"invalid compact uint prefix 0x{first:02x}")


def parse_compact_frames(data: bytes, *, transport: str) -> FrameParseResult:
    frames: list[CompactFrame] = []
    position = 0
    while position < len(data):
        frame_offset = position
        try:
            type_id, position = read_compact_uint(data, position)
            declared_length, position = read_compact_uint(data, position)
        except (EOFError, ProtocolDecodeError) as error:
            return FrameParseResult(
                frames=tuple(frames),
                partial=None,
                consumed=frame_offset,
                error=str(error),
            )
        if declared_length > MAX_FRAME_SIZE:
            return FrameParseResult(
                frames=tuple(frames),
                partial=None,
                consumed=frame_offset,
                error=f"frame length exceeds limit: {declared_length}",
            )
        payload_end = position + declared_length
        if payload_end > len(data):
            return FrameParseResult(
                frames=tuple(frames),
                partial=PartialCompactFrame(
                    offset=frame_offset,
                    type_id=type_id,
                    declared_length=declared_length,
                    payload=data[position:],
                    transport=transport,
                ),
                consumed=position,
                error=None,
            )
        frames.append(
            CompactFrame(
                offset=frame_offset,
                type_id=type_id,
                declared_length=declared_length,
                payload=data[position:payload_end],
                transport=transport,
            )
        )
        position = payload_end
    return FrameParseResult(
        frames=tuple(frames), partial=None, consumed=position, error=None
    )


def _plaintext_boundaries(data: bytes) -> tuple[tuple[int, int], ...]:
    boundaries: list[tuple[int, int]] = []
    position = 0
    while position < len(data):
        try:
            type_id, payload_offset = read_compact_uint(data, position)
            declared_length, payload_offset = read_compact_uint(data, payload_offset)
        except (EOFError, ProtocolDecodeError):
            break
        if declared_length > MAX_FRAME_SIZE:
            break
        frame_end = payload_offset + declared_length
        if frame_end > len(data):
            break
        boundaries.append((frame_end, type_id))
        position = frame_end
    return tuple(boundaries)


def decode_server_stream(reassembly: TcpReassembly, profile: CompatibilityProfile | None = None) -> DecodedServerStream:
    if reassembly.gap_bytes or reassembly.conflict_bytes:
        problems = []
        if reassembly.gap_bytes:
            problems.append(f"{reassembly.gap_bytes} missing bytes")
        if reassembly.conflict_bytes:
            problems.append(f"{reassembly.conflict_bytes} conflicting bytes")
        return DecodedServerStream(
            reassembly=reassembly,
            transport_mode="unresolved",
            plaintext_bytes=0,
            compressed_bytes=0,
            decompressed_bytes=0,
            mppc_blocks=0,
            frames=(),
            partial_frame=None,
            decode_error="TCP stream has " + " and ".join(problems),
        )

    whole_plaintext = parse_compact_frames(
        reassembly.payload, transport="plaintext"
    )
    confident_whole_plaintext = (
        bool(whole_plaintext.frames)
        # A profile handshake id is preferred, but a complete compact stream
        # is still eligible for content fallback when that id was renumbered.
        and whole_plaintext.frames[0].type_id >= 0
        and whole_plaintext.error is None
        and whole_plaintext.partial is None
        and whole_plaintext.consumed == len(reassembly.payload)
    )
    if confident_whole_plaintext:
        return DecodedServerStream(
            reassembly=reassembly,
            transport_mode="plaintext",
            plaintext_bytes=len(reassembly.payload),
            compressed_bytes=0,
            decompressed_bytes=0,
            mppc_blocks=0,
            frames=whole_plaintext.frames,
            partial_frame=None,
            decode_error=None,
        )

    best: tuple[
        tuple[int, int, int, int],
        int,
        MPPCResult,
        FrameParseResult,
    ] | None = None
    plaintext_boundaries = _plaintext_boundaries(reassembly.payload)
    prefix_frame_counts = {0: 0}
    for frame_count, (boundary, _type_id) in enumerate(
        plaintext_boundaries, start=1
    ):
        prefix_frame_counts[boundary] = frame_count
    first_key_exchange = next(
        (
            index
            for index, (_boundary, type_id) in enumerate(plaintext_boundaries)
            if type_id in (profile.key_exchange_type_ids if profile else {2})
        ),
        None,
    )
    if first_key_exchange is None:
        candidate_boundaries = (0, *[boundary for boundary, _ in plaintext_boundaries])
    else:
        candidate_boundaries = (
            *(
                boundary
                for boundary, _type_id in plaintext_boundaries[
                    first_key_exchange:
                ]
            ),
        )
    for boundary in candidate_boundaries:
        if boundary >= len(reassembly.payload):
            continue
        mppc = decompress_mppc(reassembly.payload[boundary:])
        if mppc.error or mppc.block_count == 0:
            continue
        parsed = parse_compact_frames(mppc.data, transport="mppc")
        if parsed.error or not parsed.frames:
            continue
        # A false early boundary can decode later plaintext bytes as MPPC
        # literals. Score the whole stream, then prefer the longest valid
        # plaintext prefix when both interpretations explain the same frames.
        score = (
            prefix_frame_counts[boundary] + len(parsed.frames),
            mppc.block_count,
            boundary,
            parsed.consumed,
        )
        if best is None or score > best[0]:
            best = (score, boundary, mppc, parsed)

    if best is None:
        confident_plaintext = bool(whole_plaintext.frames) and whole_plaintext.frames[0].type_id >= 0
        if reassembly.payload and not confident_plaintext:
            return DecodedServerStream(
                reassembly=reassembly,
                transport_mode="unresolved",
                plaintext_bytes=0,
                compressed_bytes=0,
                decompressed_bytes=0,
                mppc_blocks=0,
                frames=(),
                partial_frame=None,
                decode_error="unable to establish a plaintext or MPPC boundary",
            )
        return DecodedServerStream(
            reassembly=reassembly,
            transport_mode="plaintext",
            plaintext_bytes=len(reassembly.payload),
            compressed_bytes=0,
            decompressed_bytes=0,
            mppc_blocks=0,
            frames=whole_plaintext.frames,
            partial_frame=whole_plaintext.partial,
            decode_error=whole_plaintext.error,
        )

    _, boundary, mppc, compressed_frames = best
    plaintext = parse_compact_frames(
        reassembly.payload[:boundary], transport="plaintext"
    )
    decode_error = plaintext.error
    if plaintext.partial:
        decode_error = "security boundary interrupts a plaintext frame"
    return DecodedServerStream(
        reassembly=reassembly,
        transport_mode="plaintext+mppc",
        plaintext_bytes=boundary,
        compressed_bytes=len(reassembly.payload) - boundary,
        decompressed_bytes=len(mppc.data),
        mppc_blocks=mppc.block_count,
        frames=plaintext.frames + compressed_frames.frames,
        partial_frame=compressed_frames.partial,
        decode_error=decode_error,
        mppc_block_boundaries=mppc.block_boundaries,
    )


def decode_server_capture(pcap: Path) -> tuple[DecodedServerStream, ...]:
    return decode_capture_set((pcap,))[0]


def decode_client_stream(reassembly: TcpReassembly) -> DecodedClientStream:
    if reassembly.gap_bytes or reassembly.conflict_bytes:
        problems = []
        if reassembly.gap_bytes:
            problems.append(f"{reassembly.gap_bytes} missing bytes")
        if reassembly.conflict_bytes:
            problems.append(f"{reassembly.conflict_bytes} conflicting bytes")
        return DecodedClientStream(reassembly, "unresolved", (), None, "TCP stream has " + " and ".join(problems))
    parsed = parse_compact_frames(reassembly.payload, transport="plaintext")
    return DecodedClientStream(
        reassembly,
        "plaintext",
        parsed.frames,
        parsed.partial,
        parsed.error,
    )


def decode_client_capture(pcap: Path) -> tuple[DecodedClientStream, ...]:
    return decode_capture_set((pcap,))[1]


def _reassemble_by_stream(
    segments: list[TcpSegment],
) -> tuple[dict[int, TcpReassembly], dict[int, str]]:
    grouped: dict[int, list[TcpSegment]] = defaultdict(list)
    for segment in segments:
        grouped[segment.stream_id].append(segment)
    streams: dict[int, TcpReassembly] = {}
    errors: dict[int, str] = {}
    for stream_id, stream_segments in sorted(grouped.items()):
        try:
            streams[stream_id] = _reassemble_segments(stream_segments)[0]
        except ProtocolDecodeError as error:
            errors[stream_id] = str(error)
    return streams, errors


def _has_frame_type(frames: Sequence[CompactFrame], type_ids: frozenset[int]) -> bool:
    return any(frame.type_id in type_ids for frame in frames)


def _looks_like_content_auth(frames: Sequence[CompactFrame]) -> bool:
    identities: set[bytes] = set()
    for frame in frames:
        payload = frame.payload
        try:
            length, offset = read_compact_uint(payload, 0)
            if not length or offset + length > len(payload):
                continue
            candidate = payload[offset : offset + length]
        except (EOFError, ProtocolDecodeError):
            continue
        if re.fullmatch(rb"[A-Za-z0-9_.-]{2,64}\$[A-Za-z0-9_.-]{2,64}@[A-Za-z0-9_.-]{2,64}", candidate):
            identities.add(candidate)
    return len(identities) == 1


def _looks_like_content_business(frames: Sequence[CompactFrame]) -> bool:
    for frame in frames:
        payloads = [frame.payload]
        try:
            length, offset = read_compact_uint(frame.payload, 0)
            if length >= 2 and offset + length == len(frame.payload):
                payloads.append(frame.payload[offset + 2 : offset + length])
        except (EOFError, ProtocolDecodeError):
            pass
        for payload in payloads:
            parsed = parse_protobuf(payload)
            if not parsed.complete:
                continue
            details = protobuf_bytes(parsed, 2) or protobuf_bytes(parsed, 4)
            if (
                protobuf_varints(parsed, 32)
                and details
                and all(
                    (nested := parse_protobuf(item)).complete
                    and bool(protobuf_varints(nested, 1))
                    and protobuf_varints(nested, 1)[0] > 0
                    for item in details
                )
            ):
                return True
            lottery = protobuf_bytes(parsed, 7)
            if (
                protobuf_varints(parsed, 2) == (1,)
                and (not protobuf_varints(parsed, 3) or protobuf_varints(parsed, 3) == (0,))
                and lottery
                and all(
                    (nested := parse_protobuf(item)).complete
                    and bool(protobuf_varints(nested, 1))
                    and protobuf_varints(nested, 1)[0] > 0
                    and bool(protobuf_varints(nested, 5))
                    for item in lottery
                )
            ):
                return True
            shot_values = list(protobuf_varints(parsed, 6))
            for packed in protobuf_bytes(parsed, 6):
                position = 0
                try:
                    while position < len(packed):
                        value, position = read_protobuf_varint(packed, position)
                        shot_values.append(value)
                except (EOFError, ProtocolDecodeError):
                    shot_values = []
                    break
            triples = [shot_values[index : index + 3] for index in range(0, len(shot_values), 3)]
            if (
                protobuf_varints(parsed, 2) == (1,)
                and (not protobuf_varints(parsed, 3) or protobuf_varints(parsed, 3) == (0,))
                and len(shot_values) >= 6
                and len(shot_values) % 3 == 0
                and len({triple[0] for triple in triples}) == len(triples)
                and all(
                    0 < triple[0] <= 0x7FFFFFFF
                    and 0 <= triple[1] <= 0x7FFFFFFF
                    and 0 <= triple[2] <= 0x7FFFFFFF
                    for triple in triples
                )
            ):
                return True
    return False


def decode_capture_set(
    pcaps: Sequence[Path],
    profile: CompatibilityProfile | None = None,
) -> tuple[
    tuple[DecodedServerStream, ...],
    tuple[DecodedClientStream, ...],
    Counter[str],
]:
    """Decode a chronologically ordered set of capture files in one pass."""
    profile = profile or load_compatibility_profile()
    server_segments, client_segments, protocol_counts, flows = _read_capture_segments(
        pcaps, profile
    )
    server_reassemblies, server_errors = _reassemble_by_stream(server_segments)
    client_reassemblies, client_errors = _reassemble_by_stream(client_segments)
    selected_server: list[DecodedServerStream] = []
    selected_client: list[DecodedClientStream] = []

    for stream_id, flow in sorted(flows.items()):
        known_port = profile.is_known_service_port(flow.server_port)
        stream_error = server_errors.get(stream_id) or client_errors.get(stream_id)
        if known_port and stream_error:
            raise ProtocolDecodeError(
                f"target TCP stream {stream_id} could not be reassembled: {stream_error}"
            )
        if stream_error:
            continue

        server = (
            decode_server_stream(server_reassemblies[stream_id], profile)
            if stream_id in server_reassemblies
            else None
        )
        client = (
            decode_client_stream(client_reassemblies[stream_id])
            if stream_id in client_reassemblies
            else None
        )
        profile_signature_match = bool(
            client is not None and server is not None
            and _has_frame_type(client.frames, profile.client_authentication_type_ids)
            and _has_frame_type(server.frames, profile.server_handshake_type_ids)
        )
        content_signature_match = bool(
            client is not None and server is not None
            and _looks_like_content_auth(client.frames)
            and _looks_like_content_business(server.frames)
        )
        protocol_match = bool(
            flow.handshake_complete
            and server is not None
            and client is not None
            and server.decode_error is None
            and client.decode_error is None
            and server.partial_frame is None
            and client.partial_frame is None
            and (profile_signature_match or content_signature_match)
        )
        if not known_port and not protocol_match:
            continue

        locator = "profile_port" if known_port else "protocol_signature"
        if server is not None:
            selected_server.append(
                replace(
                    server,
                    reassembly=replace(
                        server.reassembly,
                        server_port=flow.server_port,
                        locator=locator,
                    ),
                )
            )
        if client is not None:
            selected_client.append(
                replace(
                    client,
                    reassembly=replace(
                        client.reassembly,
                        server_port=flow.server_port,
                        locator=locator,
                    ),
                )
            )
    return tuple(selected_server), tuple(selected_client), protocol_counts


def count_capture_protocols(
    pcaps: Sequence[Path],
    profile: CompatibilityProfile | None = None,
) -> Counter[str]:
    """Return native Scapy packet-layer counts for a capture set."""
    _server, _client, counts, _flows = _read_capture_segments(pcaps, profile)
    return counts


def unwrap_gamedata(
    frame: CompactFrame,
    *,
    stream_id: int | None = None,
    capture_id: str | None = None,
) -> GameMessage | None:
    if frame.type_id != 34:
        return None
    try:
        data_length, payload_offset = read_compact_uint(frame.payload, 0)
    except (EOFError, ProtocolDecodeError):
        return None
    payload_end = payload_offset + data_length
    if payload_end != len(frame.payload) or data_length < 2:
        return None
    data = frame.payload[payload_offset:payload_end]
    return GameMessage(
        command_id=int.from_bytes(data[:2], "little"),
        payload=data[2:],
        frame_offset=frame.offset,
        source="gamedata_candidate",
        stream_id=stream_id,
        capture_id=capture_id,
    )


def iter_game_messages(
    stream: DecodedServerStream,
    *,
    direct_ids: set[int] | None = None,
    capture_id: str | None = None,
):
    direct_ids = direct_ids or set()
    for frame in stream.frames:
        wrapped = unwrap_gamedata(
            frame,
            stream_id=stream.reassembly.stream_id,
            capture_id=capture_id,
        )
        if wrapped is not None:
            yield wrapped
        elif frame.type_id in direct_ids:
            yield GameMessage(
                command_id=frame.type_id,
                payload=frame.payload,
                frame_offset=frame.offset,
                source="direct",
                stream_id=stream.reassembly.stream_id,
                capture_id=capture_id,
            )


def read_protobuf_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        if offset >= len(data):
            raise EOFError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise ProtocolDecodeError("protobuf varint exceeds 10 bytes")


def parse_protobuf(data: bytes) -> ProtobufParseResult:
    fields: list[ProtobufField] = []
    position = 0
    try:
        while position < len(data):
            key, position = read_protobuf_varint(data, position)
            number = key >> 3
            wire_type = key & 0x07
            if number == 0:
                raise ProtocolDecodeError("protobuf field number 0 is invalid")
            if wire_type == 0:
                value, position = read_protobuf_varint(data, position)
            elif wire_type == 1:
                end = position + 8
                if end > len(data):
                    raise EOFError("truncated protobuf fixed64")
                value = int.from_bytes(data[position:end], "little")
                position = end
            elif wire_type == 2:
                length, position = read_protobuf_varint(data, position)
                end = position + length
                if end > len(data):
                    raise EOFError("truncated protobuf bytes field")
                value = data[position:end]
                position = end
            elif wire_type == 5:
                end = position + 4
                if end > len(data):
                    raise EOFError("truncated protobuf fixed32")
                value = int.from_bytes(data[position:end], "little")
                position = end
            else:
                raise ProtocolDecodeError(
                    f"unsupported protobuf wire type {wire_type}"
                )
            fields.append(ProtobufField(number, wire_type, value))
    except (EOFError, ProtocolDecodeError) as error:
        return ProtobufParseResult(
            fields=tuple(fields),
            complete=False,
            consumed=position,
            error=str(error),
        )
    return ProtobufParseResult(
        fields=tuple(fields), complete=True, consumed=position, error=None
    )


def protobuf_varints(
    parsed: ProtobufParseResult, field_number: int
) -> tuple[int, ...]:
    return tuple(
        field.value
        for field in parsed.fields
        if field.number == field_number
        and field.wire_type == 0
        and isinstance(field.value, int)
    )


def protobuf_bytes(
    parsed: ProtobufParseResult, field_number: int
) -> tuple[bytes, ...]:
    return tuple(
        field.value
        for field in parsed.fields
        if field.number == field_number
        and field.wire_type == 2
        and isinstance(field.value, bytes)
    )
