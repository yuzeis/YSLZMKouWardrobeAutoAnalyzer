from __future__ import annotations

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import PcapWriter

from YKAProtocol import (
    TcpSegment,
    _reassemble_segments,
    decode_capture_set,
    decode_server_capture,
)


SERVER = "203.0.113.10"
CLIENT = "192.0.2.20"
SERVER_PORT = 9227
CLIENT_PORT = 50000


def _packet(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    flags: str,
    payload: bytes = b"",
):
    packet = IP(src=source, dst=destination) / TCP(
        sport=source_port,
        dport=destination_port,
        seq=sequence,
        flags=flags,
    )
    return packet / Raw(payload) if payload else packet


def _write(path: Path, packets: list[object]) -> None:
    writer = PcapWriter(str(path), sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()


def test_capture_set_shares_stream_id_across_directions_and_files(
    tmp_path: Path,
) -> None:
    first = tmp_path / "segment-1.pcapng"
    second = tmp_path / "segment-2.pcapng"
    syn = _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 100, "S")
    _write(first, [syn, syn.copy()])
    _write(
        second,
        [
            _packet(SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 500, "SA"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 101, "PA", b"abc"),
            _packet(SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 501, "PA", b"def"),
        ],
    )

    server, client, counts = decode_capture_set((first, second))

    assert counts["TCP"] == 5
    assert len(server) == len(client) == 1
    assert server[0].reassembly.stream_id == client[0].reassembly.stream_id
    assert server[0].reassembly.payload == b"def"
    assert client[0].reassembly.payload == b"abc"


def test_capture_set_unwraps_32_bit_tcp_sequence_rollover(tmp_path: Path) -> None:
    capture = tmp_path / "rollover.pcapng"
    _write(
        capture,
        [
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 0xFFFFFFFC, "S"),
            _packet(
                CLIENT,
                SERVER,
                CLIENT_PORT,
                SERVER_PORT,
                0xFFFFFFFD,
                "PA",
                b"abc",
            ),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 0, "PA", b"defg"),
        ],
    )

    _server, client, _counts = decode_capture_set((capture,))

    assert len(client) == 1
    assert client[0].reassembly.payload == b"abcdefg"
    assert client[0].reassembly.gap_bytes == 0


def test_capture_set_splits_reconnected_same_tuple_into_generations(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "reconnect.pcapng"
    _write(
        capture,
        [
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 100, "S"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 101, "PA", b"a"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 102, "FA"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 1000, "S"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 1001, "PA", b"b"),
        ],
    )

    _server, client, _counts = decode_capture_set((capture,))

    assert [item.reassembly.payload for item in client] == [b"a", b"b"]
    assert [item.reassembly.stream_id for item in client] == [0, 1]


def test_reassembly_fast_path_preserves_gaps_and_overlap_conflicts() -> None:
    result = _reassemble_segments(
        [
            TcpSegment(7, 100, b"abcd"),
            TcpSegment(7, 102, b"cXef"),
            TcpSegment(7, 110, b"z"),
        ]
    )[0]

    assert result.stream_id == 7
    assert result.sequence_start == 100
    assert result.payload == b"abcdef\x00\x00\x00\x00z"
    assert result.segment_count == 3
    assert result.gap_bytes == 4
    assert result.conflict_bytes == 1


def test_server_capture_and_capture_set_share_one_reassembly_core(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "server.pcapng"
    _write(
        capture,
        [
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 100, "S"),
            _packet(SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 500, "SA"),
            _packet(SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 501, "PA", b"abc"),
        ],
    )

    direct = decode_server_capture(capture)
    capture_set, _client, _counts = decode_capture_set((capture,))

    assert direct == capture_set


def test_single_sided_fin_keeps_other_direction_in_same_generation(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "half-close.pcapng"
    _write(
        capture,
        [
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 100, "S"),
            _packet(SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 500, "SA"),
            _packet(SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 501, "PA", b"a"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 101, "PA", b"c"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 102, "FA"),
            _packet(SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 502, "PA", b"b"),
        ],
    )

    server, client, _counts = decode_capture_set((capture,))

    assert len(server) == 1
    assert server[0].reassembly.payload == b"ab"
    assert server[0].reassembly.stream_id == client[0].reassembly.stream_id


def test_rst_immediately_starts_a_new_generation(tmp_path: Path) -> None:
    capture = tmp_path / "reset.pcapng"
    _write(
        capture,
        [
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 100, "S"),
            _packet(SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 500, "SA"),
            _packet(SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 501, "PA", b"a"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 101, "RA"),
            _packet(SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 900, "PA", b"b"),
        ],
    )

    server, _client, _counts = decode_capture_set((capture,))

    assert [item.reassembly.payload for item in server] == [b"a", b"b"]
    assert [item.reassembly.stream_id for item in server] == [0, 1]


def test_syn_after_half_close_starts_new_generation_with_same_sequence(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "same-sequence-reconnect.pcapng"
    _write(
        capture,
        [
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 100, "S"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 101, "PA", b"a"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 102, "FA"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 100, "S"),
            _packet(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 101, "PA", b"b"),
        ],
    )

    _server, client, _counts = decode_capture_set((capture,))

    assert [item.reassembly.payload for item in client] == [b"a", b"b"]
    assert [item.reassembly.stream_id for item in client] == [0, 1]
