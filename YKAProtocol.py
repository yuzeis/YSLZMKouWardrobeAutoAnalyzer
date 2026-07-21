from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from YKACore import GAME_SERVICE_PORT


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


@dataclass(frozen=True)
class TcpReassembly:
    stream_id: int
    sequence_start: int
    payload: bytes
    segment_count: int
    gap_bytes: int
    conflict_bytes: int


@dataclass(frozen=True)
class MPPCResult:
    data: bytes
    block_count: int
    bits_consumed: int
    error: str | None


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
) -> tuple[list[TcpSegment], list[TcpSegment], Counter[str]]:
    try:
        from scapy.layers.inet import IP, TCP, UDP  # type: ignore[import-untyped]
        from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
        from scapy.utils import PcapReader  # type: ignore[import-untyped]
    except ImportError as error:
        raise ProtocolDecodeError("Scapy is required for offline capture analysis") from error

    server_segments: list[TcpSegment] = []
    client_segments: list[TcpSegment] = []
    protocol_counts: Counter[str] = Counter()
    active_streams: dict[tuple[int, str, int, str, int], int] = {}
    initial_syn_sequences: dict[tuple[int, str, int, str, int], int] = {}
    fin_directions: dict[tuple[int, str, int, str, int], int] = {}
    sequence_anchors: dict[tuple[int, str], int] = {}
    next_stream_id = 0

    for pcap in pcaps:
        try:
            reader = PcapReader(str(pcap))
        except (OSError, ValueError) as error:
            raise ProtocolDecodeError(f"Scapy could not open {pcap.name}: {error}") from error
        try:
            for packet in reader:
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
                if source_port != GAME_SERVICE_PORT and destination_port != GAME_SERVICE_PORT:
                    continue
                if IP in packet:
                    network = packet[IP]
                    ip_version = 4
                elif IPv6 in packet:
                    network = packet[IPv6]
                    ip_version = 6
                else:
                    continue

                if source_port == GAME_SERVICE_PORT:
                    direction = "server"
                    server_ip = str(network.src)
                    client_ip = str(network.dst)
                    client_port = destination_port
                else:
                    direction = "client"
                    server_ip = str(network.dst)
                    client_ip = str(network.src)
                    client_port = source_port
                connection = (
                    ip_version,
                    server_ip,
                    GAME_SERVICE_PORT,
                    client_ip,
                    client_port,
                )
                flags = int(tcp.flags)
                starts_connection = bool(flags & 0x02) and not bool(flags & 0x10)
                stream_id = active_streams.get(connection)
                raw_sequence = int(tcp.seq) & 0xFFFFFFFF
                if starts_connection:
                    # A SYN retransmission keeps the existing generation.  A
                    # different SYN sequence or a half-closed predecessor
                    # denotes a new connection.
                    previous_syn = initial_syn_sequences.get(connection)
                    if (
                        stream_id is None
                        or (
                            previous_syn is not None
                            and previous_syn != raw_sequence
                        )
                        or fin_directions.get(connection, 0)
                    ):
                        stream_id = next_stream_id
                        next_stream_id += 1
                        active_streams[connection] = stream_id
                        initial_syn_sequences[connection] = raw_sequence
                        fin_directions.pop(connection, None)
                elif stream_id is None:
                    stream_id = next_stream_id
                    next_stream_id += 1
                    active_streams[connection] = stream_id
                    fin_directions.pop(connection, None)

                payload = bytes(tcp.payload)
                if payload:
                    anchor_key = (stream_id, direction)
                    anchor = sequence_anchors.get(anchor_key)
                    if anchor is None:
                        sequence = raw_sequence
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
                    segment = TcpSegment(stream_id, sequence, payload)
                    if direction == "server":
                        server_segments.append(segment)
                    else:
                        client_segments.append(segment)
                if flags & 0x04:
                    active_streams.pop(connection, None)
                    initial_syn_sequences.pop(connection, None)
                    fin_directions.pop(connection, None)
                elif flags & 0x01:
                    direction_bit = 1 if direction == "server" else 2
                    finished = fin_directions.get(connection, 0) | direction_bit
                    if finished == 3:
                        active_streams.pop(connection, None)
                        initial_syn_sequences.pop(connection, None)
                        fin_directions.pop(connection, None)
                    else:
                        fin_directions[connection] = finished
        except (OSError, ValueError) as error:
            raise ProtocolDecodeError(f"Scapy failed while reading {pcap.name}: {error}") from error
        finally:
            reader.close()
    return server_segments, client_segments, protocol_counts


def _read_server_segments(pcap: Path) -> list[TcpSegment]:
    return _read_capture_segments((pcap,))[0]


def _read_client_segments(pcap: Path) -> list[TcpSegment]:
    return _read_capture_segments((pcap,))[1]


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


def decode_server_stream(reassembly: TcpReassembly) -> DecodedServerStream:
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
        and whole_plaintext.frames[0].type_id in {1, 68}
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
            if type_id == 2
        ),
        None,
    )
    if first_key_exchange is None:
        candidate_boundaries = (0,)
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
        confident_plaintext = bool(whole_plaintext.frames) and whole_plaintext.frames[0].type_id in {
            1,
            68,
        }
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
    )


def decode_server_capture(pcap: Path) -> tuple[DecodedServerStream, ...]:
    return tuple(
        decode_server_stream(reassembly)
        for reassembly in reassemble_server_streams(pcap)
    )


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
    return tuple(
        decode_client_stream(reassembly)
        for reassembly in reassemble_client_streams(pcap)
    )


def decode_capture_set(
    pcaps: Sequence[Path],
) -> tuple[
    tuple[DecodedServerStream, ...],
    tuple[DecodedClientStream, ...],
    Counter[str],
]:
    """Decode a chronologically ordered set of capture files in one pass."""
    server_segments, client_segments, protocol_counts = _read_capture_segments(pcaps)
    server_streams = tuple(
        decode_server_stream(reassembly)
        for reassembly in _reassemble_segments(server_segments)
    )
    client_streams = tuple(
        decode_client_stream(reassembly)
        for reassembly in _reassemble_segments(client_segments)
    )
    return server_streams, client_streams, protocol_counts


def count_capture_protocols(pcaps: Sequence[Path]) -> Counter[str]:
    """Return native Scapy packet-layer counts for a capture set."""
    _server, _client, counts = _read_capture_segments(pcaps)
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
