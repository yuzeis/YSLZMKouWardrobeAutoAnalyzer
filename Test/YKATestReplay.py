from __future__ import annotations

import json
from pathlib import Path

import pytest

from YKAProtocol import (
    CompactFrame,
    TcpReassembly,
    TcpSegmentSpan,
    decompress_mppc,
)
from YKAReplay import (
    DEFAULT_PROFILE_PATH,
    GNET_IDA_MODEL,
    ReplayError,
    _authentication_shape,
    _prefix_delivery_order,
    build_sanitized_trace,
    replay_sanitized_trace,
    seal_sanitized_trace,
)


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _field_varint(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def _field_bytes(number: int, value: bytes) -> bytes:
    return (
        _varint((number << 3) | 2)
        + _varint(len(value))
        + value
    )


def _synthetic_trace() -> dict[str, object]:
    fashion_detail = (
        _field_varint(1, 1001)
        + _field_varint(5, 1)
    )
    fashion_info = (
        _field_bytes(2, fashion_detail)
        + _field_varint(32, 0)
    )
    diy_detail = _field_varint(3, 7)
    diy_info = _field_bytes(2, diy_detail)
    ack = _field_varint(2, 0)

    def message(
        direction: str,
        offset: int,
        command: int,
        payload: bytes,
    ) -> dict[str, object]:
        import base64

        return {
            "direction": direction,
            "stream_id": 0,
            "frame_offset": offset,
            "delivery_order": offset,
            "command_id": command,
            "observed_opcode": command,
            "observed_wrapper_opcode": 34,
            "source": "gamedata_candidate",
            "resolution_mode": "profile",
            "payload_base64": base64.b64encode(payload).decode("ascii"),
        }

    trace: dict[str, object] = {
        "schema_version": 2,
        "mode": "offline_simulation",
        "capture_id": "capture-set:" + "0" * 16,
        "sources": [
            {
                "name": "capture-1.pcapng",
                "bytes": 1,
                "sha256": "0" * 64,
            }
        ],
        "profile": {
            "profile_id": "synthetic-profile",
            "parser_version": 1,
            "transport": "compact-mppc-v1",
            "service_ports": [9227],
            "client_authentication_type_ids": [3],
            "server_handshake_type_ids": [1],
            "key_exchange_type_ids": [2],
            "server_business_wrapper_type_ids": [34],
        },
        "redaction": {
            "authentication_payloads_included": False,
            "key_material_included": False,
            "network_addresses_included": False,
            "business_payloads_included": True,
        },
        "native_protocol_counts": {},
        "connections": [
            {
                "stream_id": 0,
                "server_port": 9227,
                "reassembly": {
                    "server_complete": True,
                    "client_complete": True,
                    "complete": True,
                },
                "transport": {
                    "server_mode": "plaintext+mppc",
                    "server_plaintext_bytes": 84,
                    "server_compressed_bytes": 20,
                    "server_decompressed_bytes": 40,
                    "server_mppc_blocks": 1,
                    "client_mode": "plaintext",
                },
                "frame_counts": {
                    "server": {"1": 1, "2": 1, "34": 2},
                    "client": {"2": 1, "3": 1, "34": 1},
                },
                "control": {
                    "server_handshake": [{"frame_type": 1}],
                    "client_authentication": [
                        {
                            "frame_type": 3,
                            "payload_bytes": 100,
                            "payload_redacted": True,
                        }
                    ],
                    "server_key_exchange": [{"frame_type": 2}],
                    "client_key_exchange": [{"frame_type": 2}],
                    "server_plaintext_control": [],
                },
                "business_messages": [
                    message("server", 10, 722, diy_info),
                    message("server", 20, 576, fashion_info),
                    message("client", 30, 143, ack),
                ],
                "ambiguous_observed_opcodes": [],
            }
        ],
    }
    return seal_sanitized_trace(trace)


def test_sanitized_trace_replays_complete_wardrobe() -> None:
    result = replay_sanitized_trace(_synthetic_trace())

    assert result["status"] == "complete"
    assert result["network_access"] is False
    assert result["requirements"]["full_wardrobe_materialized"] is True
    assert result["requirements"][
        "terminal_client_ack_order_verified"
    ] is True
    assert result["ack_ordering"]["verified"] is True
    wardrobe = result["wardrobe"]
    assert wardrobe["fashion_count"] == 2
    assert wardrobe["standard_fashion_count"] == 1
    assert wardrobe["diy_fashion_count"] == 1
    assert wardrobe["terminal_ack_seen"] is True
    assert {
        item["fashion_index"] for item in wardrobe["fashions"]
    } == {1001, 0x40000007}
    assert (
        result["gnet_ida_model"]["input_security"]["factory_7_class"]
        == "GNET::DecompressSecurity"
    )
    assert (
        result["gnet_ida_model"]["authentication"][
            "outer_type_7_semantics"
        ]
        == "unresolved_lua_or_resource_layer"
    )
    assert GNET_IDA_MODEL["input_security"][
        "arcfour_enabled_by_factory_7"
    ] is False


def test_prefix_delivery_order_handles_out_of_order_and_retransmit() -> None:
    reassembly = TcpReassembly(
        stream_id=0,
        sequence_start=100,
        payload=b"0123456789",
        segment_count=3,
        gap_bytes=0,
        conflict_bytes=0,
        segment_spans=(
            TcpSegmentSpan(5, 10, 1),
            TcpSegmentSpan(0, 5, 2),
            TcpSegmentSpan(0, 5, 3),
        ),
    )

    assert _prefix_delivery_order(reassembly, 10) == 2


def test_prefix_delivery_order_rejects_uncovered_gap() -> None:
    reassembly = TcpReassembly(
        stream_id=0,
        sequence_start=100,
        payload=b"0123456789",
        segment_count=2,
        gap_bytes=1,
        conflict_bytes=0,
        segment_spans=(
            TcpSegmentSpan(0, 4, 1),
            TcpSegmentSpan(5, 10, 2),
        ),
    )

    assert _prefix_delivery_order(reassembly, 10) is None


def test_mppc_boundaries_include_terminator_padding() -> None:
    decoded = decompress_mppc(b"abc\xf0\x00def\xf0\x00")

    assert decoded.error is None
    assert decoded.data == b"abcdef"
    assert [
        (boundary.compressed_end, boundary.decompressed_end)
        for boundary in decoded.block_boundaries
    ] == [(5, 3), (10, 6)]


def test_missing_terminal_ack_fails_closed() -> None:
    trace = _synthetic_trace()
    messages = trace["connections"][0]["business_messages"]
    trace["connections"][0]["business_messages"] = [
        value for value in messages if value["command_id"] != 143
    ]
    trace = seal_sanitized_trace(trace)

    result = replay_sanitized_trace(trace)

    assert result["status"] == "incomplete"
    assert result["wardrobe"]["snapshot_complete"] is True
    assert result["wardrobe"]["terminal_ack_seen"] is False
    assert result["wardrobe"]["full_wardrobe_complete"] is False


def test_terminal_ack_before_snapshot_fails_closed() -> None:
    trace = _synthetic_trace()
    ack = next(
        value
        for value in trace["connections"][0]["business_messages"]
        if value["command_id"] == 143
    )
    ack["delivery_order"] = 1
    trace = seal_sanitized_trace(trace)

    result = replay_sanitized_trace(trace)

    assert result["status"] == "incomplete"
    assert result["requirements"]["terminal_client_ack_observed"] is True
    assert result["requirements"][
        "terminal_client_ack_order_verified"
    ] is False
    assert result["wardrobe"]["terminal_ack_seen"] is False
    assert result["wardrobe"]["full_wardrobe_complete"] is False


def test_trace_integrity_rejects_tampering() -> None:
    trace = _synthetic_trace()
    trace["connections"][0]["server_port"] = 1

    with pytest.raises(ReplayError, match="integrity hash mismatch"):
        replay_sanitized_trace(trace)


def test_resealed_trace_rejects_sensitive_control_fields() -> None:
    trace = _synthetic_trace()
    authentication = trace["connections"][0]["control"][
        "client_authentication"
    ][0]
    authentication["payload_base64"] = "dG9rZW4="
    trace = seal_sanitized_trace(trace)

    with pytest.raises(ReplayError, match="prohibited fields"):
        replay_sanitized_trace(trace)


def test_resealed_trace_rejects_unsanitized_source_name() -> None:
    trace = _synthetic_trace()
    trace["sources"][0]["name"] = "account-device-login.pcapng"
    trace = seal_sanitized_trace(trace)

    with pytest.raises(ReplayError, match="source name"):
        replay_sanitized_trace(trace)


def test_authentication_shape_never_exports_payload() -> None:
    secret = b"account$channel@zone"
    sensitive_one = b"token-value-that-must-not-appear"
    sensitive_two = b"device-context-that-must-not-appear"
    payload = (
        bytes([len(secret)])
        + secret
        + b"\x00" * 9
        + bytes([len(sensitive_one)])
        + sensitive_one
        + bytes([len(sensitive_two)])
        + sensitive_two
    )
    frame = CompactFrame(0, 3, len(payload), payload, "plaintext")

    shape = _authentication_shape(frame)
    encoded = json.dumps(shape, sort_keys=True)

    assert shape["payload_redacted"] is True
    assert shape["leading_identity_bytes"] == len(secret)
    assert shape["fixed_header_bytes"] == 9
    assert shape["sensitive_octet_lengths"] == [
        len(sensitive_one),
        len(sensitive_two),
    ]
    assert secret.decode() not in encoded
    assert sensitive_one.decode() not in encoded
    assert sensitive_two.decode() not in encoded


REAL_CAPTURE = (
    Path(__file__).resolve().parents[2]
    / "YKAPhone-ver1.0-Preview"
    / "evidence"
    / "mumu"
    / "instance9-yslzm-20260721"
    / "4.3-final-game-login-auto.pcapng"
)


@pytest.mark.skipif(
    not REAL_CAPTURE.is_file(),
    reason="local login capture is not available",
)
def test_real_login_capture_replays_5444_fashions() -> None:
    trace = build_sanitized_trace(
        [REAL_CAPTURE],
        profile_path=DEFAULT_PROFILE_PATH,
    )
    control_json = json.dumps(
        trace["connections"][0]["control"],
        sort_keys=True,
    )

    assert "payload_base64" not in control_json
    assert trace["redaction"]["authentication_payloads_included"] is False
    assert trace["redaction"]["key_material_included"] is False
    assert trace["sources"] == [
        {
            "name": "capture-1.pcapng",
            "bytes": 375052,
            "sha256": (
                "72944e7a38b02c4a9183738d3183f26f"
                "ef30633cbbd5e4e9e00c64fb225afb6d"
            ),
        }
    ]
    assert trace["profile"]["profile_id"] == "yslzm-cn-compact-mppc-v1"
    connection = trace["connections"][0]
    assert connection["transport"]["server_plaintext_bytes"] == 84
    assert connection["transport"]["server_mppc_blocks"] == 152
    assert connection["frame_counts"]["server"]["34"] == 942
    assert connection["frame_counts"]["client"]["34"] == 6
    assert len(connection["business_messages"]) == 3
    assert [
        message["command_id"]
        for message in connection["business_messages"]
    ] == [722, 576, 143]

    result = replay_sanitized_trace(trace)
    wardrobe = result["wardrobe"]
    assert result["status"] == "complete"
    assert result["network_access"] is False
    assert result["selected_connection"] == {
        "stream_id": 0,
        "server_port": 9227,
    }
    assert result["requirements"][
        "terminal_client_ack_order_verified"
    ] is True
    assert result["ack_ordering"]["verified"] is True
    assert (
        result["ack_ordering"]["terminal_ack_delivery_orders"][0]
        > result["ack_ordering"]["completion_delivery_order"]
    )
    assert wardrobe["fashion_count"] == 5444
    assert wardrobe["standard_fashion_count"] == 5433
    assert wardrobe["diy_fashion_count"] == 11
    assert wardrobe["full_wardrobe_complete"] is True
    assert wardrobe["parse_errors"] == []
    assert wardrobe["fashion_state_sha256"] == (
        "276f2698adcaf0b1beb60c98aa92c4cc"
        "f0ca3d09fbb001388551449c3fedf697"
    )
