from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Sequence

from YKABusiness import (
    GP_ACTIVE_FASHION,
    GP_DIY_FASHION_DATA,
    GP_FASHION_EXPIRE,
    GP_FASHION_INFO,
    GP_FASHION_INFO_ACK,
    GP_FASHION_OBTAIN_SUIT,
    GP_FASHION_RENEW,
    analyze_game_messages,
)
from YKACompatibility import CompatibilityProfile, load_compatibility_profile
from YKACore import atomic_write_json, now_iso
from YKAOpcodeResolver import (
    enforce_capture_mapping_consistency,
    resolve_messages_with_diagnostics,
)
from YKAProtocol import (
    CompactFrame,
    DecodedClientStream,
    DecodedServerStream,
    GameMessage,
    MAX_FRAME_SIZE,
    ProtocolDecodeError,
    TcpReassembly,
    decode_capture_set,
    parse_protobuf,
    protobuf_varints,
    read_compact_uint,
    unwrap_gamedata,
)


TRACE_SCHEMA_VERSION = 2
RESULT_SCHEMA_VERSION = 1
REPLAY_MODE = "offline_simulation"
DEFAULT_PROFILE_PATH = (
    Path(__file__).resolve().parent
    / "DatAnDict"
    / "YKACompatibilityProfiles.json"
)
MAX_TRACE_PAYLOAD_BYTES = MAX_FRAME_SIZE

WARDROBE_COMMANDS = {
    GP_FASHION_INFO,
    GP_DIY_FASHION_DATA,
}
REPLAY_SERVER_MESSAGE_IDS = WARDROBE_COMMANDS | {
    GP_ACTIVE_FASHION,
    GP_FASHION_EXPIRE,
    GP_FASHION_RENEW,
    GP_FASHION_OBTAIN_SUIT,
}
REPLAY_GAME_MESSAGE_IDS = REPLAY_SERVER_MESSAGE_IDS | {
    GP_FASHION_INFO_ACK
}

TRACE_TOP_LEVEL_KEYS = {
    "schema_version",
    "mode",
    "capture_id",
    "sources",
    "profile",
    "redaction",
    "native_protocol_counts",
    "connections",
    "trace_sha256",
}
TRACE_PROFILE_KEYS = {
    "profile_id",
    "parser_version",
    "transport",
    "service_ports",
    "client_authentication_type_ids",
    "server_handshake_type_ids",
    "key_exchange_type_ids",
    "server_business_wrapper_type_ids",
}
TRACE_CONNECTION_KEYS = {
    "stream_id",
    "server_port",
    "reassembly",
    "transport",
    "frame_counts",
    "control",
    "business_messages",
    "ambiguous_observed_opcodes",
}
TRACE_CONTROL_KEYS = {
    "server_handshake",
    "client_authentication",
    "server_key_exchange",
    "client_key_exchange",
    "server_plaintext_control",
}
TRACE_CONTROL_EVENT_KEYS = {
    "frame_type",
    "frame_offset",
    "payload_bytes",
    "transport",
    "payload_redacted",
    "leading_octets_bytes",
    "leading_identity_bytes",
    "leading_identity_shape_valid",
    "fixed_header_bytes",
    "sensitive_octet_lengths",
}
TRACE_BUSINESS_MESSAGE_KEYS = {
    "direction",
    "stream_id",
    "frame_offset",
    "delivery_order",
    "command_id",
    "observed_opcode",
    "observed_wrapper_opcode",
    "source",
    "resolution_mode",
    "payload_base64",
}

SDK_LOGIN_MODEL = {
    "mode": "static_structure_only",
    "network_request_sent": False,
    "binary_sha256": (
        "415defe14571edcb874154f25e55a549d"
        "f6dff72818f8597facc3b91c850045f"
    ),
    "ida_evidence": {
        "lua_binding": "0x1409FA7F0",
        "signature_guard": "0x1404B8EA0",
        "request_dispatch": "0x1404B8C30",
        "login_http": "0x14049D180",
        "login_response": "0x14048FB20",
        "signature_http": "0x140492960",
        "signature_response": "0x140493760",
    },
    "login_request": {
        "endpoint_selection": [
            "account/login_with_token",
            "account2/login_with_token",
        ],
        "content_type": (
            "application/x-www-form-urlencoded;charset=UTF-8"
        ),
        "fields": [
            "appid_or_apple_id",
            "openid",
            "token",
            "dev_id",
            "dev_type",
            "dev_model",
            "dev_sys",
            "dev_carrier",
            "info",
            "sig",
        ],
    },
    "login_response_fields": [
        "rescode",
        "showname",
        "token",
        "userid_optional",
        "openid",
    ],
    "signature_refresh": {
        "endpoint": "account/get_sig",
        "fields": ["apple_id", "app_key", "dev_id", "version"],
        "version": "2.1.0",
        "response_fields": ["rescode", "sig", "time"],
    },
    "token_ttl": "server_controlled_unknown",
    "token_lifetime_evidence": {
        "local_expiry_check_observed": False,
        "exp_expires_or_ttl_field_observed": False,
        "invalidity_signal": "server_login_rescode",
        "signature_expiry_is_separate": True,
        "signature_expiry_guard": "0x1404B8EA0",
    },
}

GNET_IDA_MODEL = {
    "mode": "static_structure_only",
    "binary_sha256": SDK_LOGIN_MODEL["binary_sha256"],
    "compact_transport": {
        "receive_decoder": "0x142510B10",
        "generic_protocol_factory": "0x140849C10",
        "manager_dispatch": "0x14083AA10",
        "wire_shape": "CompactUINT(type) || CompactUINT(length) || payload",
    },
    "authentication": {
        "challenge_handler": "0x140A13F10",
        "server_challenge_type": 1,
        "client_authentication_type": 3,
        "key_exchange_handler": "0x140A154A0",
        "key_exchange_type": 2,
        "outer_type_7_semantics": "unresolved_lua_or_resource_layer",
    },
    "input_security": {
        "session_initializer": "0x1408B72D0",
        "initial_factory_id": 1,
        "initial_factory_class": "GNET::NullSecurity",
        "session_input_offset": "0x70",
        "key_exchange_factory_id": 7,
        "factory_7_registration": "0x14027D930",
        "factory_7_class": "GNET::DecompressSecurity",
        "mppc_history_bytes": 8192,
        "arcfour_enabled_by_factory_7": False,
    },
    "game_data": {
        "outer_type": 34,
        "lua_send_binding": "0x140A1B3A0",
        "send_wrapper": "0x140741F40",
        "inner_marshaller": "0x140730090",
        "receive_dispatch": "0x14088E0D0",
        "inner_shape": "uint16_le(command) || protobuf_payload",
        "wardrobe_commands": {
            "standard_snapshot": 576,
            "diy_snapshot": 722,
            "terminal_ack": 143,
        },
        "native_specific_handlers_observed": False,
        "trigger_request": "unresolved_lua_or_resource_layer",
    },
}


class ReplayError(ValueError):
    pass


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _encode_payload(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _decode_payload(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ReplayError("trace business payload is not Base64 text")
    try:
        payload = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ReplayError("trace business payload is invalid Base64") from error
    if len(payload) > MAX_TRACE_PAYLOAD_BYTES:
        raise ReplayError("trace business payload exceeds the size limit")
    return payload


def _compact_uint_size(value: int) -> int:
    if value < 0:
        raise ReplayError("compact uint cannot be negative")
    if value < 0x80:
        return 1
    if value < 0x4000:
        return 2
    if value < 0x20000000:
        return 4
    if value <= 0xFFFFFFFF:
        return 5
    raise ReplayError("compact uint exceeds the wire limit")


def _frame_end(frame: CompactFrame) -> int:
    return (
        frame.offset
        + _compact_uint_size(frame.type_id)
        + _compact_uint_size(frame.declared_length)
        + frame.declared_length
    )


def _prefix_delivery_order(
    reassembly: TcpReassembly,
    end_offset: int,
) -> int | None:
    if end_offset <= 0 or end_offset > len(reassembly.payload):
        return None
    # Return the first captured packet order at which the whole TCP prefix
    # needed by a frame was available, including out-of-order segments.
    intervals: list[tuple[int, int]] = []
    for span in sorted(
        reassembly.segment_spans,
        key=lambda item: (item.capture_order, item.start, item.end),
    ):
        if span.end <= 0 or span.start >= end_offset:
            continue
        intervals.append(
            (max(0, span.start), min(end_offset, span.end))
        )
        intervals.sort()
        covered_end = 0
        for start, end in intervals:
            if start > covered_end:
                break
            covered_end = max(covered_end, end)
            if covered_end >= end_offset:
                return span.capture_order
    return None


def _message_outer_frame(
    stream: DecodedServerStream | DecodedClientStream,
    message: GameMessage,
) -> CompactFrame | None:
    for frame in stream.frames:
        if frame.offset != message.frame_offset:
            continue
        if message.observed_wrapper_opcode is not None:
            if frame.type_id != message.observed_wrapper_opcode:
                continue
            wrapped = unwrap_gamedata(frame)
            if (
                wrapped is not None
                and wrapped.payload == message.payload
                and (
                    message.observed_opcode is None
                    or wrapped.command_id == message.observed_opcode
                )
            ):
                return frame
            continue
        if (
            message.observed_opcode is not None
            and frame.type_id == message.observed_opcode
            and frame.payload == message.payload
        ):
            return frame
    return None


def _message_delivery_order(
    stream: DecodedServerStream | DecodedClientStream,
    message: GameMessage,
) -> int | None:
    frame = _message_outer_frame(stream, message)
    if frame is None:
        return None
    frame_end = _frame_end(frame)
    if isinstance(stream, DecodedServerStream) and frame.transport == "mppc":
        # A decompressed frame is usable only after its complete MPPC block
        # has arrived; this deliberately maps to the block end, not its start.
        block = next(
            (
                boundary
                for boundary in stream.mppc_block_boundaries
                if boundary.decompressed_end >= frame_end
            ),
            None,
        )
        if block is None:
            return None
        frame_end = stream.plaintext_bytes + block.compressed_end
    return _prefix_delivery_order(stream.reassembly, frame_end)


def _first_octets_length(payload: bytes) -> int | None:
    try:
        length, offset = read_compact_uint(payload, 0)
    except (EOFError, ProtocolDecodeError):
        return None
    if offset + length > len(payload):
        return None
    return length


def _authentication_shape(frame: CompactFrame) -> dict[str, Any]:
    payload = frame.payload
    shape: dict[str, Any] = {
        "frame_type": frame.type_id,
        "frame_offset": frame.offset,
        "payload_bytes": len(payload),
        "payload_redacted": True,
    }
    try:
        identity_length, identity_offset = read_compact_uint(payload, 0)
    except (EOFError, ProtocolDecodeError):
        return shape
    identity_end = identity_offset + identity_length
    if identity_end > len(payload):
        return shape

    identity = payload[identity_offset:identity_end]
    shape["leading_identity_bytes"] = identity_length
    shape["leading_identity_shape_valid"] = bool(
        re.fullmatch(
            rb"[A-Za-z0-9_.-]{2,64}\$"
            rb"[A-Za-z0-9_.-]{2,64}@"
            rb"[A-Za-z0-9_.-]{2,64}",
            identity,
        )
    )

    scan_end = min(len(payload), identity_end + 64)
    for candidate in range(identity_end, scan_end + 1):
        try:
            first_length, first_offset = read_compact_uint(
                payload, candidate
            )
            first_end = first_offset + first_length
            second_length, second_offset = read_compact_uint(
                payload, first_end
            )
            second_end = second_offset + second_length
        except (EOFError, ProtocolDecodeError):
            continue
        if second_end != len(payload):
            continue
        shape["fixed_header_bytes"] = candidate - identity_end
        shape["sensitive_octet_lengths"] = [
            first_length,
            second_length,
        ]
        break
    return shape


def _frame_evidence(
    frame: CompactFrame,
    *,
    authentication: bool = False,
) -> dict[str, Any]:
    if authentication:
        return _authentication_shape(frame)
    evidence = {
        "frame_type": frame.type_id,
        "frame_offset": frame.offset,
        "payload_bytes": len(frame.payload),
        "transport": frame.transport,
        "payload_redacted": True,
    }
    leading_length = _first_octets_length(frame.payload)
    if leading_length is not None:
        evidence["leading_octets_bytes"] = leading_length
    return evidence


def _message_to_trace(
    message: GameMessage,
    *,
    direction: str,
    stream: DecodedServerStream | DecodedClientStream,
) -> dict[str, Any]:
    return {
        "direction": direction,
        "stream_id": message.stream_id,
        "frame_offset": message.frame_offset,
        "delivery_order": _message_delivery_order(stream, message),
        "command_id": message.command_id,
        "observed_opcode": message.observed_opcode,
        "observed_wrapper_opcode": message.observed_wrapper_opcode,
        "source": message.source,
        "resolution_mode": message.resolution_mode,
        "payload_base64": _encode_payload(message.payload),
    }


def _stream_complete(stream: Any) -> bool:
    if stream is None:
        return False
    reassembly = stream.reassembly
    return bool(
        not reassembly.gap_bytes
        and not reassembly.conflict_bytes
        and stream.decode_error is None
        and stream.partial_frame is None
    )


def seal_sanitized_trace(trace: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(trace)
    sealed.pop("trace_sha256", None)
    sealed["trace_sha256"] = _canonical_sha256(sealed)
    return sealed


def _verify_trace_integrity(trace: dict[str, Any]) -> None:
    expected = trace.get("trace_sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        raise ReplayError("trace integrity hash is missing")
    unhashed = dict(trace)
    unhashed.pop("trace_sha256", None)
    actual = _canonical_sha256(unhashed)
    if actual != expected:
        raise ReplayError("trace integrity hash mismatch")


def _require_exact_keys(
    value: Any,
    expected: set[str],
    context: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReplayError(f"{context} is not an object")
    actual = set(value)
    if actual != expected:
        unexpected = sorted(actual - expected)
        missing = sorted(expected - actual)
        details = []
        if unexpected:
            details.append("unexpected=" + ",".join(unexpected))
        if missing:
            details.append("missing=" + ",".join(missing))
        raise ReplayError(
            f"{context} schema is invalid ({'; '.join(details)})"
        )
    return value


def _require_nonnegative_int(value: Any, context: str) -> int:
    if type(value) is not int or value < 0:
        raise ReplayError(f"{context} is not a nonnegative integer")
    return value


def _require_int_list(value: Any, context: str) -> list[int]:
    if not isinstance(value, list):
        raise ReplayError(f"{context} is not an integer list")
    for index, item in enumerate(value):
        _require_nonnegative_int(item, f"{context}[{index}]")
    return value


def _validate_control_event(value: Any, context: str) -> None:
    if not isinstance(value, dict):
        raise ReplayError(f"{context} is not an object")
    unexpected = set(value) - TRACE_CONTROL_EVENT_KEYS
    if unexpected:
        raise ReplayError(
            f"{context} has prohibited fields: {','.join(sorted(unexpected))}"
        )
    if "frame_type" not in value:
        raise ReplayError(f"{context}.frame_type is missing")
    integer_fields = {
        "frame_type",
        "frame_offset",
        "payload_bytes",
        "leading_octets_bytes",
        "leading_identity_bytes",
        "fixed_header_bytes",
    }
    for field in integer_fields & set(value):
        _require_nonnegative_int(value[field], f"{context}.{field}")
    for field in {
        "payload_redacted",
        "leading_identity_shape_valid",
    } & set(value):
        if type(value[field]) is not bool:
            raise ReplayError(f"{context}.{field} is not boolean")
    if "payload_redacted" in value and value["payload_redacted"] is not True:
        raise ReplayError(f"{context} contains an unredacted payload")
    if "transport" in value and value["transport"] not in {
        "plaintext",
        "mppc",
    }:
        raise ReplayError(f"{context}.transport is invalid")
    if "sensitive_octet_lengths" in value:
        _require_int_list(
            value["sensitive_octet_lengths"],
            f"{context}.sensitive_octet_lengths",
        )


def _validate_trace_schema(trace: dict[str, Any]) -> None:
    _require_exact_keys(trace, TRACE_TOP_LEVEL_KEYS, "trace")
    capture_id = trace.get("capture_id")
    if not isinstance(capture_id, str) or not re.fullmatch(
        r"capture-set:[0-9a-f]{16}",
        capture_id,
    ):
        raise ReplayError("trace capture id is not a sanitized identifier")

    sources = trace.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ReplayError("trace sources are missing")
    for index, source_value in enumerate(sources, start=1):
        source = _require_exact_keys(
            source_value,
            {"name", "bytes", "sha256"},
            f"trace.sources[{index - 1}]",
        )
        if source.get("name") not in {
            f"capture-{index}.pcap",
            f"capture-{index}.pcapng",
        }:
            raise ReplayError("trace source name is not sanitized")
        _require_nonnegative_int(
            source.get("bytes"),
            f"trace.sources[{index - 1}].bytes",
        )
        if not isinstance(source.get("sha256"), str) or not re.fullmatch(
            r"[0-9a-f]{64}",
            source["sha256"],
        ):
            raise ReplayError("trace source hash is invalid")

    profile = _require_exact_keys(
        trace.get("profile"),
        TRACE_PROFILE_KEYS,
        "trace.profile",
    )
    if not isinstance(profile.get("profile_id"), str) or not re.fullmatch(
        r"[a-z][a-z0-9-]{0,63}",
        profile["profile_id"],
    ):
        raise ReplayError("trace profile id is invalid")
    _require_nonnegative_int(
        profile.get("parser_version"),
        "trace.profile.parser_version",
    )
    if profile.get("transport") != "compact-mppc-v1":
        raise ReplayError("trace profile transport is unsupported")
    for field in TRACE_PROFILE_KEYS - {
        "profile_id",
        "parser_version",
        "transport",
    }:
        _require_int_list(profile.get(field), f"trace.profile.{field}")

    redaction = _require_exact_keys(
        trace.get("redaction"),
        {
            "authentication_payloads_included",
            "key_material_included",
            "network_addresses_included",
            "business_payloads_included",
        },
        "trace.redaction",
    )
    if redaction != {
        "authentication_payloads_included": False,
        "key_material_included": False,
        "network_addresses_included": False,
        "business_payloads_included": True,
    }:
        raise ReplayError("trace redaction declaration is invalid")

    counts = trace.get("native_protocol_counts")
    if not isinstance(counts, dict):
        raise ReplayError("trace native protocol counts are invalid")
    for name, count in counts.items():
        if not isinstance(name, str) or not re.fullmatch(
            r"[A-Za-z0-9_.:+-]{1,64}",
            name,
        ):
            raise ReplayError("trace native protocol name is invalid")
        _require_nonnegative_int(count, f"trace.native_protocol_counts.{name}")

    connections = trace.get("connections")
    if not isinstance(connections, list) or not connections:
        raise ReplayError("trace has no replayable connections")
    for connection_index, connection_value in enumerate(connections):
        context = f"trace.connections[{connection_index}]"
        connection = _require_exact_keys(
            connection_value,
            TRACE_CONNECTION_KEYS,
            context,
        )
        stream_id = _require_nonnegative_int(
            connection.get("stream_id"),
            f"{context}.stream_id",
        )
        server_port = connection.get("server_port")
        if server_port is not None:
            server_port = _require_nonnegative_int(
                server_port,
                f"{context}.server_port",
            )
            if server_port > 65535:
                raise ReplayError(f"{context}.server_port is invalid")

        reassembly = _require_exact_keys(
            connection.get("reassembly"),
            {"server_complete", "client_complete", "complete"},
            f"{context}.reassembly",
        )
        if any(type(value) is not bool for value in reassembly.values()):
            raise ReplayError(f"{context}.reassembly contains non-booleans")

        transport = _require_exact_keys(
            connection.get("transport"),
            {
                "server_mode",
                "server_plaintext_bytes",
                "server_compressed_bytes",
                "server_decompressed_bytes",
                "server_mppc_blocks",
                "client_mode",
            },
            f"{context}.transport",
        )
        if transport["server_mode"] not in {
            "plaintext",
            "plaintext+mppc",
            "unobserved",
            "unresolved",
        } or transport["client_mode"] not in {
            "plaintext",
            "unobserved",
            "unresolved",
        }:
            raise ReplayError(f"{context}.transport mode is invalid")
        for field in {
            "server_plaintext_bytes",
            "server_compressed_bytes",
            "server_decompressed_bytes",
            "server_mppc_blocks",
        }:
            _require_nonnegative_int(
                transport[field],
                f"{context}.transport.{field}",
            )

        frame_counts = _require_exact_keys(
            connection.get("frame_counts"),
            {"server", "client"},
            f"{context}.frame_counts",
        )
        for direction, direction_counts in frame_counts.items():
            if not isinstance(direction_counts, dict):
                raise ReplayError(
                    f"{context}.frame_counts.{direction} is invalid"
                )
            for frame_type, count in direction_counts.items():
                if not isinstance(frame_type, str) or not re.fullmatch(
                    r"(?:0|[1-9][0-9]{0,9})",
                    frame_type,
                ):
                    raise ReplayError(
                        f"{context}.frame_counts.{direction} key is invalid"
                    )
                _require_nonnegative_int(
                    count,
                    f"{context}.frame_counts.{direction}.{frame_type}",
                )

        control = _require_exact_keys(
            connection.get("control"),
            TRACE_CONTROL_KEYS,
            f"{context}.control",
        )
        for category, events in control.items():
            if not isinstance(events, list):
                raise ReplayError(
                    f"{context}.control.{category} is not a list"
                )
            for event_index, event in enumerate(events):
                _validate_control_event(
                    event,
                    f"{context}.control.{category}[{event_index}]",
                )

        messages = connection.get("business_messages")
        if not isinstance(messages, list):
            raise ReplayError(f"{context}.business_messages is not a list")
        for message_index, message_value in enumerate(messages):
            message_context = (
                f"{context}.business_messages[{message_index}]"
            )
            message = _require_exact_keys(
                message_value,
                TRACE_BUSINESS_MESSAGE_KEYS,
                message_context,
            )
            if message.get("direction") not in {"server", "client"}:
                raise ReplayError(f"{message_context}.direction is invalid")
            if message.get("stream_id") != stream_id:
                raise ReplayError(f"{message_context}.stream_id is invalid")
            _require_nonnegative_int(
                message.get("frame_offset"),
                f"{message_context}.frame_offset",
            )
            delivery_order = message.get("delivery_order")
            if delivery_order is not None:
                _require_nonnegative_int(
                    delivery_order,
                    f"{message_context}.delivery_order",
                )
                if delivery_order == 0:
                    raise ReplayError(
                        f"{message_context}.delivery_order is invalid"
                    )
            command_id = _require_nonnegative_int(
                message.get("command_id"),
                f"{message_context}.command_id",
            )
            if command_id not in REPLAY_GAME_MESSAGE_IDS:
                raise ReplayError(
                    f"{message_context}.command_id is outside replay scope"
                )
            for field in {"observed_opcode", "observed_wrapper_opcode"}:
                observed = message.get(field)
                if observed is not None:
                    _require_nonnegative_int(
                        observed,
                        f"{message_context}.{field}",
                    )
            source = message.get("source")
            if not isinstance(source, str) or not re.fullmatch(
                r"(?:gamedata_candidate|direct|"
                r"content_fallback:outer=[0-9]+,inner=[0-9]+)",
                source,
            ):
                raise ReplayError(f"{message_context}.source is invalid")
            if message.get("resolution_mode") not in {
                "profile",
                "content_fallback",
            }:
                raise ReplayError(
                    f"{message_context}.resolution_mode is invalid"
                )
            _decode_payload(message.get("payload_base64"))

        _require_int_list(
            connection.get("ambiguous_observed_opcodes"),
            f"{context}.ambiguous_observed_opcodes",
        )


def build_sanitized_trace(
    pcaps: Sequence[Path],
    *,
    profile_path: Path | None = None,
) -> dict[str, Any]:
    if not pcaps:
        raise ReplayError("at least one PCAP or PCAPNG file is required")
    capture_paths = tuple(Path(path).expanduser().resolve() for path in pcaps)
    source_entries: list[dict[str, Any]] = []
    for source_index, path in enumerate(capture_paths, start=1):
        if not path.is_file():
            raise ReplayError(f"capture file does not exist: {path}")
        suffix = path.suffix.lower()
        if suffix not in {".pcap", ".pcapng"}:
            suffix = ".pcap"
        source_entries.append(
            {
                "name": f"capture-{source_index}{suffix}",
                "bytes": path.stat().st_size,
                "sha256": _file_sha256(path),
            }
        )

    selected_profile_path = (
        Path(profile_path).expanduser().resolve()
        if profile_path is not None
        else DEFAULT_PROFILE_PATH
    )
    profile = load_compatibility_profile(selected_profile_path)
    servers, clients, protocol_counts = decode_capture_set(
        capture_paths, profile
    )
    capture_id = "capture-set:" + _canonical_sha256(source_entries)[:16]
    server_by_stream = {
        stream.reassembly.stream_id: stream for stream in servers
    }
    client_by_stream = {
        stream.reassembly.stream_id: stream for stream in clients
    }
    connections: list[dict[str, Any]] = []

    for stream_id in sorted(set(server_by_stream) | set(client_by_stream)):
        server = server_by_stream.get(stream_id)
        client = client_by_stream.get(stream_id)
        server_frames = tuple(server.frames) if server is not None else ()
        client_frames = tuple(client.frames) if client is not None else ()

        server_resolution = (
            resolve_messages_with_diagnostics(
                server, profile, capture_id=capture_id
            )
            if server is not None
            else None
        )
        client_resolution = (
            resolve_messages_with_diagnostics(
                client, profile, capture_id=capture_id
            )
            if client is not None
            else None
        )
        raw_server_messages = (
            server_resolution.messages if server_resolution is not None else ()
        )
        raw_client_messages = (
            client_resolution.messages if client_resolution is not None else ()
        )
        server_consistency = enforce_capture_mapping_consistency(
            raw_server_messages
        )
        client_consistency = enforce_capture_mapping_consistency(
            raw_client_messages
        )

        server_handshake = [
            _frame_evidence(frame)
            for frame in server_frames
            if frame.type_id in profile.server_handshake_type_ids
        ]
        client_authentication = [
            _frame_evidence(frame, authentication=True)
            for frame in client_frames
            if frame.type_id in profile.client_authentication_type_ids
        ]
        server_key_exchange = [
            _frame_evidence(frame)
            for frame in server_frames
            if frame.type_id in profile.key_exchange_type_ids
        ]
        client_key_exchange = [
            _frame_evidence(frame)
            for frame in client_frames
            if frame.type_id in profile.key_exchange_type_ids
        ]
        server_plaintext_control = [
            _frame_evidence(frame)
            for frame in server_frames
            if frame.transport == "plaintext"
        ]

        business_messages = [
            _message_to_trace(
                message,
                direction="server",
                stream=server,
            )
            for message in server_consistency.messages
            if (
                server is not None
                and message.command_id in REPLAY_SERVER_MESSAGE_IDS
            )
        ]
        business_messages.extend(
            _message_to_trace(
                message,
                direction="client",
                stream=client,
            )
            for message in client_consistency.messages
            if (
                client is not None
                and message.command_id == GP_FASHION_INFO_ACK
            )
        )

        server_port = (
            server.reassembly.server_port
            if server is not None
            else (
                client.reassembly.server_port
                if client is not None
                else None
            )
        )
        connections.append(
            {
                "stream_id": stream_id,
                "server_port": server_port,
                "reassembly": {
                    "server_complete": _stream_complete(server),
                    "client_complete": _stream_complete(client),
                    "complete": (
                        _stream_complete(server)
                        and _stream_complete(client)
                    ),
                },
                "transport": {
                    "server_mode": (
                        server.transport_mode
                        if server is not None
                        else "unobserved"
                    ),
                    "server_plaintext_bytes": (
                        server.plaintext_bytes if server is not None else 0
                    ),
                    "server_compressed_bytes": (
                        server.compressed_bytes if server is not None else 0
                    ),
                    "server_decompressed_bytes": (
                        server.decompressed_bytes if server is not None else 0
                    ),
                    "server_mppc_blocks": (
                        server.mppc_blocks if server is not None else 0
                    ),
                    "client_mode": (
                        client.transport_mode
                        if client is not None
                        else "unobserved"
                    ),
                },
                "frame_counts": {
                    "server": {
                        str(type_id): count
                        for type_id, count in sorted(
                            Counter(
                                frame.type_id for frame in server_frames
                            ).items()
                        )
                    },
                    "client": {
                        str(type_id): count
                        for type_id, count in sorted(
                            Counter(
                                frame.type_id for frame in client_frames
                            ).items()
                        )
                    },
                },
                "control": {
                    "server_handshake": server_handshake,
                    "client_authentication": client_authentication,
                    "server_key_exchange": server_key_exchange,
                    "client_key_exchange": client_key_exchange,
                    "server_plaintext_control": server_plaintext_control,
                },
                "business_messages": business_messages,
                "ambiguous_observed_opcodes": sorted(
                    set(server_consistency.ambiguous_observed_opcodes)
                    | set(client_consistency.ambiguous_observed_opcodes)
                ),
            }
        )

    trace = {
        "schema_version": TRACE_SCHEMA_VERSION,
        "mode": REPLAY_MODE,
        "capture_id": capture_id,
        "sources": source_entries,
        "profile": {
            "profile_id": profile.profile_id,
            "parser_version": profile.parser_version,
            "transport": profile.transport,
            "service_ports": sorted(profile.service_ports),
            "client_authentication_type_ids": sorted(
                profile.client_authentication_type_ids
            ),
            "server_handshake_type_ids": sorted(
                profile.server_handshake_type_ids
            ),
            "key_exchange_type_ids": sorted(
                profile.key_exchange_type_ids
            ),
            "server_business_wrapper_type_ids": sorted(
                profile.server_business_wrapper_type_ids
            ),
        },
        "redaction": {
            "authentication_payloads_included": False,
            "key_material_included": False,
            "network_addresses_included": False,
            "business_payloads_included": True,
        },
        "native_protocol_counts": {
            name: count for name, count in protocol_counts.most_common()
        },
        "connections": connections,
    }
    return seal_sanitized_trace(trace)


def _load_trace_message(
    value: Any,
    *,
    capture_id: str,
    stream_id: int,
) -> tuple[str, GameMessage]:
    if not isinstance(value, dict):
        raise ReplayError("trace business message is not an object")
    direction = value.get("direction")
    if direction not in {"server", "client"}:
        raise ReplayError("trace business direction is invalid")
    command_id = value.get("command_id")
    frame_offset = value.get("frame_offset")
    if type(command_id) is not int or command_id <= 0:
        raise ReplayError("trace business command id is invalid")
    if type(frame_offset) is not int or frame_offset < 0:
        raise ReplayError("trace business frame offset is invalid")
    payload = _decode_payload(value.get("payload_base64"))
    message = GameMessage(
        command_id=command_id,
        payload=payload,
        frame_offset=frame_offset,
        source=str(value.get("source") or "sanitized_trace"),
        stream_id=stream_id,
        capture_id=capture_id,
        resolution_mode=str(
            value.get("resolution_mode") or "sanitized_trace"
        ),
        observed_opcode=(
            value.get("observed_opcode")
            if type(value.get("observed_opcode")) is int
            else None
        ),
        observed_wrapper_opcode=(
            value.get("observed_wrapper_opcode")
            if type(value.get("observed_wrapper_opcode")) is int
            else None
        ),
        delivery_order=(
            value.get("delivery_order")
            if type(value.get("delivery_order")) is int
            else None
        ),
    )
    return direction, message


def _wardrobe_summary(wardrobe: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "status",
        "snapshot_observed",
        "snapshot_complete",
        "standard_wardrobe_complete",
        "full_wardrobe_complete",
        "snapshot_messages",
        "snapshot_fragments",
        "terminal_cursor_seen",
        "terminal_ack_seen",
        "ack_cursors",
        "fashion_count",
        "standard_fashion_count",
        "diy_fashion_count",
        "diy_snapshot_observed",
        "parse_errors",
    )
    return {field: wardrobe.get(field) for field in fields}


def _replay_connection(
    connection: dict[str, Any],
    *,
    capture_id: str,
) -> dict[str, Any]:
    stream_id = connection.get("stream_id")
    if type(stream_id) is not int or stream_id < 0:
        raise ReplayError("trace connection stream id is invalid")
    values = connection.get("business_messages")
    if not isinstance(values, list):
        raise ReplayError("trace connection business messages are missing")

    server_messages: list[GameMessage] = []
    client_messages: list[GameMessage] = []
    for value in values:
        direction, message = _load_trace_message(
            value,
            capture_id=capture_id,
            stream_id=stream_id,
        )
        if direction == "server":
            server_messages.append(message)
        else:
            client_messages.append(message)
    server_messages.sort(key=lambda message: message.frame_offset)
    client_messages.sort(key=lambda message: message.frame_offset)

    replay_states: list[dict[str, Any]] = []
    applied_server: list[GameMessage] = []
    for message in server_messages:
        applied_server.append(message)
        if message.command_id not in WARDROBE_COMMANDS:
            continue
        state = analyze_game_messages(applied_server)[
            "data_coverage"
        ]["wardrobe_presence"]
        replay_states.append(
            {
                "phase": "server_business_message",
                "command_id": message.command_id,
                "frame_offset": message.frame_offset,
                "wardrobe": _wardrobe_summary(state),
            }
        )

    ack_events: list[dict[str, int | None]] = []
    for message in client_messages:
        if message.command_id != GP_FASHION_INFO_ACK:
            continue
        parsed = parse_protobuf(message.payload)
        cursors = protobuf_varints(parsed, 2)
        if not parsed.complete or not cursors:
            continue
        cursor = int(cursors[0])
        ack_events.append(
            {
                "cursor": cursor,
                "frame_offset": message.frame_offset,
                "delivery_order": message.delivery_order,
            }
        )

    terminal_snapshots: list[GameMessage] = []
    diy_snapshots: list[GameMessage] = []
    for message in server_messages:
        if message.command_id == GP_FASHION_INFO:
            parsed = parse_protobuf(message.payload)
            if (
                parsed.complete
                and 0 in protobuf_varints(parsed, 32)
            ):
                terminal_snapshots.append(message)
        elif message.command_id == GP_DIY_FASHION_DATA:
            parsed = parse_protobuf(message.payload)
            if parsed.complete:
                diy_snapshots.append(message)
    terminal_snapshot = (
        terminal_snapshots[-1] if terminal_snapshots else None
    )
    diy_snapshot = diy_snapshots[-1] if diy_snapshots else None
    snapshot_delivery_orders = [
        message.delivery_order
        for message in (terminal_snapshot, diy_snapshot)
        if message is not None and message.delivery_order is not None
    ]
    completion_delivery_order = (
        max(snapshot_delivery_orders)
        if (
            terminal_snapshot is not None
            and diy_snapshot is not None
            and len(snapshot_delivery_orders) == 2
        )
        else None
    )
    observed_terminal_ack = any(
        event["cursor"] == 0 for event in ack_events
    )
    ordered_ack_events = [
        event
        for event in ack_events
        if (
            completion_delivery_order is not None
            and event["delivery_order"] is not None
            and event["delivery_order"] > completion_delivery_order
        )
    ]
    ack_order_verified = any(
        event["cursor"] == 0 for event in ordered_ack_events
    )
    ack_cursors = [
        int(event["cursor"])
        for event in ordered_ack_events
        if event["cursor"] is not None
    ]
    for event in ack_events:
        replay_states.append(
            {
                "phase": "client_wardrobe_ack",
                "command_id": GP_FASHION_INFO_ACK,
                "frame_offset": event["frame_offset"],
                "delivery_order": event["delivery_order"],
                "cursor": event["cursor"],
                "order_verified": bool(
                    completion_delivery_order is not None
                    and event["delivery_order"] is not None
                    and event["delivery_order"]
                    > completion_delivery_order
                ),
            }
        )

    ack_map = (
        {(capture_id, stream_id): ack_cursors}
        if ack_cursors
        else {}
    )
    business = analyze_game_messages(
        server_messages,
        wardrobe_ack_cursors=ack_map,
    )
    wardrobe = business["data_coverage"]["wardrobe_presence"]
    control = connection.get("control")
    if not isinstance(control, dict):
        control = {}
    transport = connection.get("transport")
    if not isinstance(transport, dict):
        transport = {}
    reassembly = connection.get("reassembly")
    if not isinstance(reassembly, dict):
        reassembly = {}
    frame_counts = connection.get("frame_counts")
    if not isinstance(frame_counts, dict):
        frame_counts = {}
    server_counts = frame_counts.get("server")
    if not isinstance(server_counts, dict):
        server_counts = {}
    wrapper_observed = bool(
        int(server_counts.get("34", 0) or 0) > 0
        or any(
            message.observed_wrapper_opcode == 34
            for message in server_messages
        )
    )
    requirements = {
        "sdk_http_login_modeled": True,
        "tcp_reassembled": bool(reassembly.get("complete")),
        "server_handshake_observed": bool(
            control.get("server_handshake")
        ),
        "client_authentication_observed": bool(
            control.get("client_authentication")
        ),
        "server_key_exchange_observed": bool(
            control.get("server_key_exchange")
        ),
        "client_key_exchange_observed": bool(
            control.get("client_key_exchange")
        ),
        "server_mppc_transition_observed": bool(
            transport.get("server_mode") == "plaintext+mppc"
            and int(transport.get("server_mppc_blocks", 0) or 0) > 0
        ),
        "business_wrapper_observed": wrapper_observed,
        "standard_wardrobe_snapshot_observed": any(
            message.command_id == GP_FASHION_INFO
            for message in server_messages
        ),
        "diy_wardrobe_snapshot_observed": any(
            message.command_id == GP_DIY_FASHION_DATA
            for message in server_messages
        ),
        "terminal_client_ack_observed": bool(
            observed_terminal_ack
        ),
        "terminal_client_ack_order_verified": bool(
            ack_order_verified
        ),
        "full_wardrobe_materialized": bool(
            wardrobe.get("full_wardrobe_complete")
        ),
    }
    complete = all(requirements.values())
    return {
        "stream_id": stream_id,
        "server_port": connection.get("server_port"),
        "status": "complete" if complete else "incomplete",
        "requirements": requirements,
        "transport": transport,
        "control": control,
        "business_message_counts": {
            str(command_id): count
            for command_id, count in sorted(
                Counter(
                    message.command_id for message in server_messages
                ).items()
            )
        },
        "client_message_counts": {
            str(command_id): count
            for command_id, count in sorted(
                Counter(
                    message.command_id for message in client_messages
                ).items()
            )
        },
        "replay_states": replay_states,
        "ack_ordering": {
            "terminal_snapshot_delivery_order": (
                terminal_snapshot.delivery_order
                if terminal_snapshot is not None
                else None
            ),
            "diy_snapshot_delivery_order": (
                diy_snapshot.delivery_order
                if diy_snapshot is not None
                else None
            ),
            "completion_delivery_order": completion_delivery_order,
            "terminal_ack_delivery_orders": [
                event["delivery_order"]
                for event in ack_events
                if event["cursor"] == 0
            ],
            "verified": ack_order_verified,
        },
        "wardrobe": wardrobe,
    }


def replay_sanitized_trace(
    trace: dict[str, Any],
    *,
    include_fashions: bool = True,
) -> dict[str, Any]:
    if not isinstance(trace, dict):
        raise ReplayError("trace root is not an object")
    if trace.get("schema_version") != TRACE_SCHEMA_VERSION:
        raise ReplayError("unsupported replay trace schema")
    if trace.get("mode") != REPLAY_MODE:
        raise ReplayError("trace is not an offline simulation")
    _verify_trace_integrity(trace)
    _validate_trace_schema(trace)

    capture_id = trace.get("capture_id")
    if not isinstance(capture_id, str) or not capture_id:
        raise ReplayError("trace capture id is missing")
    connections = trace.get("connections")
    if not isinstance(connections, list) or not connections:
        raise ReplayError("trace has no replayable connections")

    replayed = [
        _replay_connection(connection, capture_id=capture_id)
        for connection in connections
        if isinstance(connection, dict)
    ]
    if not replayed:
        raise ReplayError("trace has no valid connection objects")
    selected = max(
        replayed,
        key=lambda item: (
            item["status"] == "complete",
            bool(
                item["wardrobe"].get("full_wardrobe_complete")
            ),
            int(item["wardrobe"].get("fashion_count") or 0),
        ),
    )
    wardrobe = dict(selected["wardrobe"])
    fashions = wardrobe.get("fashions")
    if isinstance(fashions, list):
        wardrobe["fashion_state_sha256"] = _canonical_sha256(fashions)
    if not include_fashions:
        wardrobe.pop("fashions", None)
        wardrobe.pop("deltas", None)

    phases = [
        {
            "phase": "sdk_login_structure",
            "status": "modeled",
            "network_request_sent": False,
        },
        {
            "phase": "tcp_reassembly",
            "status": (
                "observed"
                if selected["requirements"]["tcp_reassembled"]
                else "missing"
            ),
        },
        {
            "phase": "server_handshake",
            "status": (
                "observed"
                if selected["requirements"][
                    "server_handshake_observed"
                ]
                else "missing"
            ),
        },
        {
            "phase": "client_authentication",
            "status": (
                "observed_redacted"
                if selected["requirements"][
                    "client_authentication_observed"
                ]
                else "missing"
            ),
        },
        {
            "phase": "key_exchange",
            "status": (
                "observed_redacted"
                if (
                    selected["requirements"][
                        "server_key_exchange_observed"
                    ]
                    and selected["requirements"][
                        "client_key_exchange_observed"
                    ]
                )
                else "missing"
            ),
        },
        {
            "phase": "server_mppc_transition",
            "status": (
                "observed"
                if selected["requirements"][
                    "server_mppc_transition_observed"
                ]
                else "missing"
            ),
        },
        {
            "phase": "wardrobe_business_replay",
            "status": (
                "materialized"
                if selected["requirements"][
                    "full_wardrobe_materialized"
                ]
                else "incomplete"
            ),
        },
        {
            "phase": "terminal_ack_ordering",
            "status": (
                "verified"
                if selected["requirements"][
                    "terminal_client_ack_order_verified"
                ]
                else "unverified"
            ),
        },
    ]
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "generated_at": now_iso(),
        "mode": REPLAY_MODE,
        "status": selected["status"],
        "network_access": False,
        "trace_sha256": trace["trace_sha256"],
        "capture_id": capture_id,
        "sources": trace.get("sources", []),
        "profile": trace.get("profile", {}),
        "selected_connection": {
            "stream_id": selected["stream_id"],
            "server_port": selected["server_port"],
        },
        "requirements": selected["requirements"],
        "phases": phases,
        "sdk_login_model": SDK_LOGIN_MODEL,
        "gnet_ida_model": GNET_IDA_MODEL,
        "transport": selected["transport"],
        "business_message_counts": selected[
            "business_message_counts"
        ],
        "client_message_counts": selected["client_message_counts"],
        "ack_ordering": selected["ack_ordering"],
        "replay_states": selected["replay_states"],
        "wardrobe": wardrobe,
        "connection_results": [
            {
                "stream_id": item["stream_id"],
                "server_port": item["server_port"],
                "status": item["status"],
                "requirements": item["requirements"],
                "fashion_count": item["wardrobe"].get("fashion_count"),
            }
            for item in replayed
        ],
        "privacy": {
            "authentication_payloads_replayed": False,
            "key_material_replayed": False,
            "business_payloads_replayed_offline": True,
            "raw_token_output": False,
        },
        "semantics": (
            "This result is a deterministic offline state reconstruction. "
            "The generated_at field is informational. It "
            "models the SDK login request shape from IDA evidence, verifies "
            "the redacted GNET authentication and key-exchange frame shapes, "
            "replays only captured business protobuf payloads, and never "
            "opens a network connection. Cross-direction completion uses "
            "capture packet delivery order and conservative MPPC block "
            "boundaries rather than unrelated per-direction offsets."
        ),
    }


def replay_capture(
    pcaps: Sequence[Path],
    *,
    profile_path: Path | None = None,
    include_fashions: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    trace = build_sanitized_trace(pcaps, profile_path=profile_path)
    result = replay_sanitized_trace(
        trace,
        include_fashions=include_fashions,
    )
    return trace, result


def _read_trace(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReplayError(f"cannot read replay trace: {error}") from error
    if not isinstance(value, dict):
        raise ReplayError("replay trace root is not an object")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replay the YSLZM login-to-wardrobe chain offline without "
            "sending authentication or game traffic."
        )
    )
    parser.add_argument(
        "captures",
        nargs="*",
        type=Path,
        help="chronologically ordered PCAP/PCAPNG files",
    )
    parser.add_argument(
        "--trace",
        type=Path,
        help="replay an existing sanitized trace instead of PCAP files",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=DEFAULT_PROFILE_PATH,
        help="compatibility profile registry",
    )
    parser.add_argument(
        "--trace-output",
        type=Path,
        help="write the deterministic sanitized trace",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the offline replay result",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="omit the full fashion list from the result",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.trace is not None:
            if args.captures:
                raise ReplayError(
                    "capture paths and --trace are mutually exclusive"
                )
            trace = _read_trace(args.trace.expanduser().resolve())
            result = replay_sanitized_trace(
                trace,
                include_fashions=not args.summary_only,
            )
        else:
            trace, result = replay_capture(
                args.captures,
                profile_path=args.profile,
                include_fashions=not args.summary_only,
            )
        if args.trace_output is not None:
            atomic_write_json(
                args.trace_output.expanduser().resolve(),
                trace,
            )
        if args.output is not None:
            atomic_write_json(
                args.output.expanduser().resolve(),
                result,
            )
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("status") == "complete" else 2
    except (OSError, ValueError, ProtocolDecodeError) as error:
        print(f"offline replay failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
