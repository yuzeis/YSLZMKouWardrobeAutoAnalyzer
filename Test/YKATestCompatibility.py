from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import PcapWriter

import YKACompatibility
from YKACompatibility import (
    SignedConfigurationUnavailable,
    generic_content_profile,
    load_compatibility_profile,
)
from YKAOpcodeResolver import resolve_messages
from YKAProtocol import CompactFrame, DecodedClientStream, DecodedServerStream, TcpReassembly
from YKAProtocol import decode_capture_set
from YKAReport import _decode_game_traffic
from YKAWechatImport import generate_import_code_from_report


SERVER = "203.0.113.10"
CLIENT = "192.0.2.20"
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


def _compact(value: int) -> bytes:
    if value < 128:
        return bytes((value,))
    if value < 16384:
        return bytes((0x80 | (value >> 8), value & 0xFF))
    raise ValueError("test value is too large")


def _frame(type_id: int, payload: bytes = b"") -> bytes:
    return _compact(type_id) + _compact(len(payload)) + payload


def _mppc_literals(data: bytes) -> bytes:
    bits = "".join(
        ("0" + format(value, "07b"))
        if value < 0x80
        else ("10" + format(value & 0x7F, "07b"))
        for value in data
    )
    bits += "1111000000"
    bits += "0" * ((-len(bits)) % 8)
    return bytes(int(bits[index : index + 8], 2) for index in range(0, len(bits), 8))


def test_protocol_signature_discovers_moved_service_port(tmp_path: Path) -> None:
    server_port = 44333
    identity = b"100000000000001$fixture@01"
    capture = tmp_path / "moved-port.pcapng"
    _write(
        capture,
        [
            _packet(CLIENT, SERVER, CLIENT_PORT, server_port, 100, "S"),
            _packet(SERVER, CLIENT, server_port, CLIENT_PORT, 500, "SA"),
            _packet(CLIENT, SERVER, CLIENT_PORT, server_port, 101, "PA", _frame(3, identity)),
            _packet(SERVER, CLIENT, server_port, CLIENT_PORT, 501, "PA", _frame(1)),
        ],
    )

    server, client, counts = decode_capture_set((capture,))

    assert counts["TCP"] == 4
    assert len(server) == len(client) == 1
    assert server[0].reassembly.server_port == server_port
    assert server[0].reassembly.locator == "protocol_signature"
    assert [frame.type_id for frame in server[0].frames] == [1]
    assert [frame.type_id for frame in client[0].frames] == [3]


def test_unrelated_tls_flow_does_not_become_game_candidate(tmp_path: Path) -> None:
    capture = tmp_path / "tls.pcapng"
    tls = b"\x16\x03\x03\x00\x01\x00"
    _write(
        capture,
        [
            _packet(CLIENT, SERVER, CLIENT_PORT, 443, 100, "S"),
            _packet(SERVER, CLIENT, 443, CLIENT_PORT, 500, "SA"),
            _packet(CLIENT, SERVER, CLIENT_PORT, 443, 101, "PA", tls),
            _packet(SERVER, CLIENT, 443, CLIENT_PORT, 501, "PA", tls),
        ],
    )

    server, client, counts = decode_capture_set((capture,))

    assert counts["TCP"] == 4
    assert server == ()
    assert client == ()


def test_android_and_desktop_ship_byte_identical_profiles() -> None:
    root = Path(__file__).resolve().parents[2]
    desktop = root / "YKA-Ver1.0-Preview" / "DatAnDict" / "YKACompatibilityProfiles.json"
    android = root / "YKAPhone-ver1.0-Preview" / "app" / "src" / "main" / "assets" / "yka" / "YKACompatibilityProfiles.json"
    if not desktop.is_file() or not android.is_file():
        pytest.skip("optional paired desktop/Android checkouts are not available")

    assert desktop.read_bytes() == android.read_bytes()
    assert load_compatibility_profile(desktop).profile_id == "yslzm-cn-compact-mppc-v1"


def test_missing_signed_configuration_uses_only_explicit_generic_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        YKACompatibility,
        "load_config_snapshot_or_none",
        lambda: None,
    )

    with pytest.raises(SignedConfigurationUnavailable):
        load_compatibility_profile()

    generic = generic_content_profile()
    assert generic.profile_id == "generic-content-fallback"
    assert generic.catalog_bundle_id == ""
    assert all(not opcodes for opcodes in generic.business_opcodes.values())


def test_desktop_and_android_actual_capture_export_is_byte_identical() -> None:
    root = Path(__file__).resolve().parents[2]
    evidence = root / "YKAPhone-ver1.0-Preview" / "evidence" / "mumu" / "instance9-yslzm-20260722-beta3-final"
    pcap = evidence / "archive" / "superseded-runtime-runs" / "runtime-final" / "YKAPhone-live-final.pcapng"
    expected_path = evidence / "runtime-strict-final" / "yka-auto-import.json"
    if not pcap.is_file() or not expected_path.is_file():
        pytest.skip("private cross-platform integration evidence is not available")
    expected = expected_path.read_bytes()
    protocol, coverage, errors = _decode_game_traffic([pcap])
    result = generate_import_code_from_report(
        {"generated_at": "verification", "protocol_decode": protocol, "data_coverage": coverage},
        Path("DatAnDict/YKAPoolCatalog.json"),
    )
    actual = result.code.encode("utf-8")

    assert errors == []
    assert protocol["status"] == "decoded"
    assert protocol["compatibility_profile"]["resolution_mode"] == "profile"
    assert protocol["compatibility_profile"]["ambiguous_observed_opcodes"] == []
    assert len(result.records) == 329
    assert len(actual) == 9541
    assert actual == expected
    assert hashlib.sha256(actual).hexdigest().upper() == "F3EB41A084FDBE4B294E46896FF58ABBE90081A6316FC7BF079655CAC0A93A90"


def test_unsupported_profile_parser_fails_closed(tmp_path: Path) -> None:
    source = Path("DatAnDict/YKACompatibilityProfiles.json")
    document = json.loads(source.read_text(encoding="utf-8"))
    document["profiles"][0]["parser_version"] = 2
    invalid = tmp_path / "invalid-profile.json"
    invalid.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported parser"):
        load_compatibility_profile(invalid)


def test_profile_cannot_bind_a_different_compact_catalog(tmp_path: Path) -> None:
    source = Path("DatAnDict/YKACompatibilityProfiles.json")
    document = json.loads(source.read_text(encoding="utf-8"))
    document["profiles"][0]["catalog_bundle_id"] = "00000101"
    invalid = tmp_path / "wrong-catalog-profile.json"
    invalid.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match loaded catalog"):
        load_compatibility_profile(invalid)


def test_profile_rejects_non_eight_digit_catalog_id(tmp_path: Path) -> None:
    source = Path("DatAnDict/YKACompatibilityProfiles.json")
    document = json.loads(source.read_text(encoding="utf-8"))
    document["profiles"][0]["catalog_bundle_id"] = "102"
    invalid = tmp_path / "short-catalog-profile.json"
    invalid.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="catalog bundle is invalid"):
        load_compatibility_profile(invalid)


def test_profile_rejects_duplicate_business_opcode(tmp_path: Path) -> None:
    source = Path("DatAnDict/YKACompatibilityProfiles.json")
    document = json.loads(source.read_text(encoding="utf-8"))
    document["profiles"][0]["business_opcodes"]["photo_info"] = [576]
    invalid = tmp_path / "duplicate-opcode-profile.json"
    invalid.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="overlaps"):
        load_compatibility_profile(invalid)


def test_profile_rejects_overlapping_server_protocol_types(tmp_path: Path) -> None:
    source = Path("DatAnDict/YKACompatibilityProfiles.json")
    document = json.loads(source.read_text(encoding="utf-8"))
    document["profiles"][0]["protocol_signature"]["key_exchange_type_ids"] = [1]
    invalid = tmp_path / "overlapping-protocol-profile.json"
    invalid.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="type ids overlap"):
        load_compatibility_profile(invalid)


def test_content_fallback_resolves_renumbered_wrapper() -> None:
    def varint(value: int) -> bytes:
        output = bytearray()
        while value > 127:
            output.append((value & 0x7F) | 0x80)
            value >>= 7
        output.append(value)
        return bytes(output)

    detail = varint(8) + varint(123)
    payload = varint(256) + varint(1) + varint(18) + varint(len(detail)) + detail
    inner = (999).to_bytes(2, "little") + payload
    wrapped = varint(len(inner)) + inner
    frame = CompactFrame(0, 777, len(wrapped), wrapped, "plaintext")
    stream = DecodedServerStream(
        TcpReassembly(1, 0, b"", 1, 0, 0),
        "plaintext", 0, 0, 0, 0, (frame,), None, None,
    )

    messages = resolve_messages(stream, load_compatibility_profile())

    assert [(message.command_id, message.source, message.resolution_mode) for message in messages] == [
        (576, "gamedata_candidate", "content_fallback")
    ]


def test_content_fallback_ambiguity_is_unknown() -> None:
    frame = CompactFrame(0, 777, 2, b"\x00\x00", "plaintext")
    stream = DecodedServerStream(
        TcpReassembly(1, 0, b"", 1, 0, 0),
        "plaintext", 0, 0, 0, 0, (frame,), None, None,
    )
    assert resolve_messages(stream, load_compatibility_profile()) == ()


def test_content_fallback_rejects_cross_frame_opcode_conflict() -> None:
    def vi(value: int) -> bytes:
        out = bytearray()
        while value > 127:
            out.append((value & 0x7F) | 0x80)
            value >>= 7
        out.append(value)
        return bytes(out)

    wardrobe_detail = vi(8) + vi(123)
    wardrobe = vi(256) + vi(0) + vi(18) + vi(len(wardrobe_detail)) + wardrobe_detail
    draw_detail = vi(8) + vi(9) + vi(40) + vi(1)
    lottery = vi(16) + vi(1) + vi(58) + vi(len(draw_detail)) + draw_detail
    frames = (
        CompactFrame(0, 9001, len(wardrobe), wardrobe, "plaintext"),
        CompactFrame(1, 9001, len(lottery), lottery, "plaintext"),
    )
    stream = DecodedServerStream(
        TcpReassembly(1, 0, b"", 1, 0, 0),
        "plaintext", 0, 0, 0, 0, frames, None, None,
    )

    assert resolve_messages(stream, load_compatibility_profile()) == ()


def test_full_content_fallback_pipeline_with_shifted_opcodes(tmp_path: Path) -> None:
    def vi(value: int) -> bytes:
        out = bytearray()
        while value > 127:
            out.append((value & 0x7F) | 0x80)
            value >>= 7
        out.append(value)
        return bytes(out)

    def field(number: int, value: int) -> bytes:
        return vi(number << 3) + vi(value)

    def bytes_field(number: int, value: bytes) -> bytes:
        return vi((number << 3) | 2) + vi(len(value)) + value

    identity = b"100000000000001$fixture@01"
    wardrobe = field(32, 0) + bytes_field(2, field(1, 1001))
    lottery_record = field(1, 7) + field(5, 2)
    lottery = field(2, 1) + bytes_field(7, lottery_record)
    shot = field(2, 1) + bytes_field(6, vi(11) + vi(3) + vi(100) + vi(12) + vi(1) + vi(101))
    wrapper = lambda command, payload: vi(len(command.to_bytes(2, "little") + payload)) + command.to_bytes(2, "little") + payload
    compressed_business = b"".join(
        (
            _frame(903, wrapper(1600, wardrobe)),
            _frame(903, wrapper(1601, lottery)),
            _frame(903, wrapper(1602, shot)),
        )
    )
    server_payload = _frame(902) + _frame(904) + _mppc_literals(compressed_business)
    client_payload = _frame(901, field(2, 0)) + _frame(
        900, vi(len(identity)) + identity + field(1, 1)
    )
    capture = tmp_path / "shifted-full.pcapng"
    _write(capture, [
        _packet(CLIENT, SERVER, CLIENT_PORT, 44333, 100, "S"),
        _packet(SERVER, CLIENT, 44333, CLIENT_PORT, 500, "SA"),
        _packet(CLIENT, SERVER, CLIENT_PORT, 44333, 101, "PA", client_payload),
        _packet(SERVER, CLIENT, 44333, CLIENT_PORT, 501, "PA", server_payload),
    ])
    servers, clients, _ = decode_capture_set((capture,))
    assert len(servers) == len(clients) == 1
    profile = load_compatibility_profile()
    server_messages = resolve_messages(servers[0], profile)
    client_messages = resolve_messages(clients[0], profile)
    assert {message.command_id for message in server_messages} >= {576, 737, 740}
    assert all(message.resolution_mode == "content_fallback" for message in server_messages)
    assert any(message.command_id == 143 for message in client_messages)
    assert {message.observed_wrapper_opcode for message in server_messages} == {903}
    assert {message.observed_opcode for message in server_messages} == {1600, 1601, 1602}
    assert servers[0].transport_mode == "plaintext+mppc"


@pytest.mark.parametrize("payload", [
    _frame(900, b"not-an-identity"),
    _frame(900, b"100000000000001$fixture@01"),
    _frame(900, b"\x08\x01\x12\x01x"),
    _frame(903, b"\x05\x00\x00"),
    b"\x16\x03\x03\x00\x01\x00",
])
def test_content_fallback_pipeline_rejects_missing_or_malformed_identity(tmp_path: Path, payload: bytes) -> None:
    capture = tmp_path / "rejected.pcapng"
    _write(capture, [
        _packet(CLIENT, SERVER, CLIENT_PORT, 45555, 100, "S"),
        _packet(SERVER, CLIENT, 45555, CLIENT_PORT, 500, "SA"),
        _packet(CLIENT, SERVER, CLIENT_PORT, 45555, 101, "PA", payload),
        _packet(SERVER, CLIENT, 45555, CLIENT_PORT, 501, "PA", _frame(902)),
    ])
    servers, clients, _ = decode_capture_set((capture,))
    assert servers == () and clients == ()


def test_profile_opcode_payload_conflict_falls_back_to_content() -> None:
    detail = b"\x10\x00"
    frame = CompactFrame(0, 576, len(detail), detail, "plaintext")
    stream = DecodedClientStream(
        TcpReassembly(1, 0, b"", 1, 0, 0),
        "plaintext", (frame,), None, None,
    )
    messages = resolve_messages(stream, load_compatibility_profile())
    assert messages and messages[0].command_id == 143 and messages[0].resolution_mode == "content_fallback"


def test_ack_fingerprint_is_not_used_for_unknown_server_messages() -> None:
    detail = b"\x10\x00"
    frame = CompactFrame(0, 9001, len(detail), detail, "plaintext")
    stream = DecodedServerStream(
        TcpReassembly(1, 0, b"", 1, 0, 0),
        "plaintext", 0, 0, 0, 0, (frame,), None, None,
    )
    assert resolve_messages(stream, load_compatibility_profile()) == ()


def test_validated_profile_evidence_suppresses_same_semantic_fallback() -> None:
    ack = b"\x10\x00"
    frames = (
        CompactFrame(0, 143, len(ack), ack, "plaintext"),
        CompactFrame(1, 9001, len(ack), ack, "plaintext"),
    )
    stream = DecodedClientStream(
        TcpReassembly(1, 0, b"", 1, 0, 0), "plaintext", frames, None, None,
    )
    messages = resolve_messages(stream, load_compatibility_profile())
    assert [(message.command_id, message.resolution_mode) for message in messages] == [
        (143, "profile")
    ]


def test_two_fallback_opcodes_for_one_semantic_fail_closed() -> None:
    ack = b"\x10\x00"
    frames = (
        CompactFrame(0, 9001, len(ack), ack, "plaintext"),
        CompactFrame(1, 9002, len(ack), ack, "plaintext"),
    )
    stream = DecodedClientStream(
        TcpReassembly(1, 0, b"", 1, 0, 0), "plaintext", frames, None, None,
    )
    assert resolve_messages(stream, load_compatibility_profile()) == ()


def test_malformed_configured_opcode_fails_closed() -> None:
    frame = CompactFrame(0, 576, 1, b"\x80", "plaintext")
    stream = DecodedServerStream(
        TcpReassembly(1, 0, b"", 1, 0, 0),
        "plaintext", 0, 0, 0, 0, (frame,), None, None,
    )

    assert resolve_messages(stream, load_compatibility_profile()) == ()


def test_configured_business_opcodes_are_directional() -> None:
    wardrobe_detail = b"\x08\x7b"
    wardrobe = b"\x80\x02\x00\x12\x02" + wardrobe_detail
    server_only = CompactFrame(0, 576, len(wardrobe), wardrobe, "plaintext")
    client_stream = DecodedClientStream(
        TcpReassembly(1, 0, b"", 1, 0, 0),
        "plaintext", (server_only,), None, None,
    )
    ack = CompactFrame(0, 143, 2, b"\x10\x00", "plaintext")
    server_stream = DecodedServerStream(
        TcpReassembly(1, 0, b"", 1, 0, 0),
        "plaintext", 0, 0, 0, 0, (ack,), None, None,
    )

    assert resolve_messages(client_stream, load_compatibility_profile()) == ()
    assert resolve_messages(server_stream, load_compatibility_profile()) == ()


@pytest.mark.parametrize(
    "payload",
    [
        b"\x10\x01\x10\x01\x3a\x04\x08\x07\x28\x02",
        b"\x10\x01\x18\x02\x3a\x04\x08\x07\x28\x02",
    ],
)
def test_lottery_fingerprint_rejects_duplicate_operation_or_error(
    payload: bytes,
) -> None:
    frame = CompactFrame(0, 9001, len(payload), payload, "plaintext")
    stream = DecodedServerStream(
        TcpReassembly(1, 0, b"", 1, 0, 0),
        "plaintext", 0, 0, 0, 0, (frame,), None, None,
    )

    assert resolve_messages(stream, load_compatibility_profile()) == ()
