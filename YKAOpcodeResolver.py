"""Profile-first game message resolver with content-based opcode fallback."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from YKACompatibility import CompatibilityProfile
from YKABusiness import (
    GP_ACTIVE_FASHION, GP_DIY_FASHION_DATA, GP_FASHION_EXPIRE,
    GP_FASHION_INFO_ACK, GP_FASHION_INFO, GP_FASHION_OBTAIN_SUIT,
    GP_FASHION_RENEW, GP_LUCKYDRAW_OPERATE_RE, GP_PHOTO_INFO,
    GP_PHOTO_OPERATE_RE,
)
from YKAProtocol import (
    CompactFrame, DecodedClientStream, DecodedServerStream, GameMessage,
    parse_protobuf, protobuf_bytes, protobuf_varints, read_compact_uint,
    read_protobuf_varint,
)

SEMANTIC_IDS = {
    "fashion_info_ack": GP_FASHION_INFO_ACK,
    "fashion_info": GP_FASHION_INFO,
    "active_fashion": GP_ACTIVE_FASHION,
    "fashion_expire": GP_FASHION_EXPIRE,
    "fashion_renew": GP_FASHION_RENEW,
    "photo_info": GP_PHOTO_INFO,
    "diy_fashion_data": GP_DIY_FASHION_DATA,
    "fashion_obtain_suit": GP_FASHION_OBTAIN_SUIT,
    "luckydraw_operate_re": GP_LUCKYDRAW_OPERATE_RE,
    "photo_operate_re": GP_PHOTO_OPERATE_RE,
}
_WARDROBE = {"fashion_info", "active_fashion", "fashion_expire", "fashion_renew", "diy_fashion_data", "fashion_obtain_suit"}
_SERVER_FALLBACK_SEMANTICS = {"fashion_info", "luckydraw_operate_re", "photo_operate_re"}
_CLIENT_FALLBACK_SEMANTICS = {"fashion_info_ack"}


@dataclass(frozen=True)
class ResolutionResult:
    messages: tuple[GameMessage, ...]
    ambiguous_observed_opcodes: frozenset[int]


def _complete(data: bytes):
    parsed = parse_protobuf(data)
    return parsed if parsed.complete else None


def _nested_has_id(data: bytes, field: int = 1) -> bool:
    parsed = _complete(data)
    return bool(parsed and protobuf_varints(parsed, field) and protobuf_varints(parsed, field)[0] > 0)


def _looks_like(semantic: str, payload: bytes) -> bool:
    parsed = _complete(payload)
    if parsed is None:
        return False
    if semantic == "fashion_info_ack":
        return protobuf_varints(parsed, 2) == (0,) and len(parsed.fields) == 1
    if semantic == "fashion_info":
        details = protobuf_bytes(parsed, 2) or protobuf_bytes(parsed, 4)
        return bool(protobuf_varints(parsed, 32)) and bool(details) and all(_nested_has_id(item) for item in details)
    if semantic in {"active_fashion", "fashion_renew"}:
        return bool(protobuf_bytes(parsed, 2)) and all(_nested_has_id(item) for item in protobuf_bytes(parsed, 2)) and not protobuf_varints(parsed, 32)
    if semantic == "fashion_expire":
        return bool(protobuf_varints(parsed, 2)) and not protobuf_bytes(parsed, 2)
    if semantic == "fashion_obtain_suit":
        return protobuf_varints(parsed, 2) in ((), (0,)) and bool(protobuf_bytes(parsed, 4)) and all(_nested_has_id(item) for item in protobuf_bytes(parsed, 4))
    if semantic == "luckydraw_operate_re":
        records = protobuf_bytes(parsed, 7)
        return (
            protobuf_varints(parsed, 2) == (1,)
            and protobuf_varints(parsed, 3) in ((), (0,))
            and all(
            _nested_has_id(item) and bool((nested := _complete(item)) and protobuf_varints(nested, 5))
            for item in records
            )
            and bool(records)
        )
    if semantic == "photo_operate_re":
        values = list(protobuf_varints(parsed, 6))
        for packed in protobuf_bytes(parsed, 6):
            pos = 0
            try:
                while pos < len(packed):
                    value, pos = read_protobuf_varint(packed, pos)
                    values.append(value)
            except (EOFError, ValueError):
                return False
        triples = [tuple(values[i:i + 3]) for i in range(0, len(values) - 2, 3)]
        ids = [item[0] for item in triples]
        return (
            protobuf_varints(parsed, 2) == (1,)
            and protobuf_varints(parsed, 3) in ((), (0,))
            and len(values) >= 6
            and len(values) % 3 == 0
            and len(set(ids)) == len(ids)
            and all(0 < item[0] <= 0x7FFFFFFF and 0 <= item[1] <= 0x7FFFFFFF and 0 <= item[2] <= 0x7FFFFFFF for item in triples)
        )
    if semantic == "photo_info":
        return not protobuf_varints(parsed, 32) and bool(protobuf_bytes(parsed, 2)) and bool(protobuf_bytes(parsed, 3)) and all(_nested_has_id(item) for item in protobuf_bytes(parsed, 2) + protobuf_bytes(parsed, 3))
    if semantic == "diy_fashion_data":
        return not protobuf_varints(parsed, 32) and bool(protobuf_bytes(parsed, 3)) and all(
            bool(protobuf_varints(nested, 3)) for raw in protobuf_bytes(parsed, 3)
            if (nested := _complete(raw)) is not None
        )
    return False


def _unwrap(frame: CompactFrame, *, fallback: bool = False) -> tuple[int, bytes] | None:
    try:
        length, offset = read_compact_uint(frame.payload, 0)
    except Exception:
        return None
    if length < 2 or offset + length != len(frame.payload):
        return None
    data = frame.payload[offset:offset + length]
    return int.from_bytes(data[:2], "little"), data[2:]


def _message(command: int, payload: bytes, frame: CompactFrame, source: str, stream_id: int | None, capture_id: str | None, *, mode: str, observed: int, wrapper: int | None) -> GameMessage:
    legacy_source = "gamedata_candidate" if wrapper is not None else "direct"
    return GameMessage(command, payload, frame.offset, legacy_source, stream_id, capture_id, mode, observed, wrapper)


def _without_ambiguous_observed_mappings(
    messages: list[GameMessage] | tuple[GameMessage, ...],
) -> ResolutionResult:
    profile_semantics = {
        message.command_id
        for message in messages
        if message.resolution_mode == "profile" and _profile_payload_validated(message)
    }
    messages = [
        message
        for message in messages
        if message.resolution_mode != "content_fallback"
        or message.command_id not in profile_semantics
    ]
    mappings: defaultdict[int, set[int]] = defaultdict(set)
    for message in messages:
        if message.observed_opcode is not None:
            mappings[message.observed_opcode].add(message.command_id)
    ambiguous = {
        opcode for opcode, semantics in mappings.items() if len(semantics) > 1
    }
    fallback_opcodes: defaultdict[int, set[int]] = defaultdict(set)
    for message in messages:
        if message.resolution_mode == "content_fallback" and message.observed_opcode is not None:
            fallback_opcodes[message.command_id].add(message.observed_opcode)
    for opcodes in fallback_opcodes.values():
        if len(opcodes) > 1:
            ambiguous.update(opcodes)
    ambiguous_set = frozenset(ambiguous)
    return ResolutionResult(
        tuple(message for message in messages if message.observed_opcode not in ambiguous_set),
        ambiguous_set,
    )


def _profile_payload_validated(message: GameMessage) -> bool:
    semantic = next(
        (name for name, command_id in SEMANTIC_IDS.items() if command_id == message.command_id),
        None,
    )
    return bool(semantic and _profile_payload_is_valid(semantic, message.payload))


def _profile_payload_is_valid(semantic: str, payload: bytes) -> bool:
    return _complete(payload) is not None


def resolve_messages_with_diagnostics(
    stream: DecodedServerStream | DecodedClientStream,
    profile: CompatibilityProfile,
    *,
    capture_id: str | None = None,
) -> ResolutionResult:
    """Return normalized semantic messages; fallback is accepted only when unique."""
    client_direction = isinstance(stream, DecodedClientStream)
    allowed_profile_semantics = (
        _CLIENT_FALLBACK_SEMANTICS
        if client_direction
        else set(SEMANTIC_IDS) - _CLIENT_FALLBACK_SEMANTICS
    )
    configured = {
        opcode: name
        for name, values in profile.business_opcodes.items()
        if name in allowed_profile_semantics
        for opcode in values
    }
    fallback_semantics = (
        _CLIENT_FALLBACK_SEMANTICS
        if client_direction
        else _SERVER_FALLBACK_SEMANTICS
    )
    result: list[GameMessage] = []
    for frame in stream.frames:
        candidates: list[tuple[int, bytes, str, int | None]] = []
        if frame.type_id in configured:
            candidates.append((frame.type_id, frame.payload, "profile", None))
        elif frame.type_id not in profile.server_business_wrapper_type_ids:
            candidates.append((frame.type_id, frame.payload, "content_fallback", None))
        if (
            frame.type_id in profile.server_business_wrapper_type_ids
            or frame.type_id not in configured
        ):
            wrapped = _unwrap(frame)
            if wrapped:
                candidates.append((wrapped[0], wrapped[1], "profile" if frame.type_id in profile.server_business_wrapper_type_ids else "content_fallback", frame.type_id))
        evidence: dict[str, tuple[int, bytes, str, int | None]] = {}
        for observed, payload, source, wrapper in candidates:
            configured_semantic = configured.get(observed)
            matches = [name for name in fallback_semantics if _looks_like(name, payload)]
            if (
                configured_semantic
                and _profile_payload_is_valid(configured_semantic, payload)
                and (not matches or matches == [configured_semantic])
            ):
                evidence.setdefault(configured_semantic, (observed, payload, source, wrapper))
            elif len(matches) == 1:
                evidence.setdefault(matches[0], (observed, payload, "content_fallback", wrapper))
        if len(evidence) == 1:
            semantic, (observed, payload, source, wrapper) = next(iter(evidence.items()))
            if source == "content_fallback":
                source = f"content_fallback:outer={frame.type_id},inner={observed}"
            mode = "content_fallback" if source == "content_fallback" or source.startswith("content_fallback:") else "profile"
            observed_wrapper = wrapper
            result.append(_message(SEMANTIC_IDS[semantic], payload, frame, source, stream.reassembly.stream_id, capture_id, mode=mode, observed=observed, wrapper=observed_wrapper))
    return _without_ambiguous_observed_mappings(result)


def resolve_messages(stream: DecodedServerStream | DecodedClientStream, profile: CompatibilityProfile, *, capture_id: str | None = None) -> tuple[GameMessage, ...]:
    return resolve_messages_with_diagnostics(
        stream, profile, capture_id=capture_id
    ).messages


def enforce_capture_mapping_consistency(
    messages: list[GameMessage] | tuple[GameMessage, ...],
) -> ResolutionResult:
    """Reject an observed opcode that maps to multiple semantics in one capture."""
    return _without_ambiguous_observed_mappings(messages)
