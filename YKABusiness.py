from __future__ import annotations

import struct
from collections import defaultdict
from typing import Any, Iterable

from YKAProtocol import (
    GameMessage,
    ProtobufParseResult,
    parse_protobuf,
    protobuf_bytes,
    protobuf_varints,
    read_protobuf_varint,
)


GP_FASHION_INFO_ACK = 143
GP_FASHION_INFO = 576
GP_ACTIVE_FASHION = 577
GP_FASHION_EXPIRE = 609
GP_FASHION_RENEW = 610
GP_DIY_FASHION_DATA = 722
GP_FASHION_OBTAIN_SUIT = 734
GP_LUCKYDRAW_OPERATE_RE = 737
GP_PHOTO_INFO = 637
TARGET_GAME_MESSAGE_IDS = {
    GP_FASHION_INFO,
    GP_ACTIVE_FASHION,
    GP_FASHION_EXPIRE,
    GP_FASHION_RENEW,
    GP_DIY_FASHION_DATA,
    GP_FASHION_OBTAIN_SUIT,
    GP_LUCKYDRAW_OPERATE_RE,
    GP_PHOTO_INFO,
}


def _evidence_metadata(messages: Iterable[GameMessage]) -> dict[str, Any]:
    sources = sorted({message.source for message in messages})
    candidate_sources = {
        source for source in sources if source.endswith("candidate")
    }
    if not sources:
        level = "none"
    elif candidate_sources == set(sources):
        level = "candidate"
    elif candidate_sources:
        level = "mixed"
    elif sources == ["direct"]:
        level = "direct"
    else:
        level = "other"
    return {"evidence_level": level, "evidence_sources": sources}


def _signed_int32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _first_varint(
    parsed: ProtobufParseResult, field_number: int, default: int | None = None
) -> int | None:
    values = protobuf_varints(parsed, field_number)
    return _signed_int32(values[0]) if values else default


def _repeated_int32(
    parsed: ProtobufParseResult, field_number: int
) -> tuple[int, ...]:
    values = [_signed_int32(value) for value in protobuf_varints(parsed, field_number)]
    for packed in protobuf_bytes(parsed, field_number):
        position = 0
        try:
            while position < len(packed):
                value, position = read_protobuf_varint(packed, position)
                values.append(_signed_int32(value))
        except (EOFError, ValueError):
            continue
    return tuple(values)


def _first_fixed32(
    parsed: ProtobufParseResult, field_number: int
) -> int | None:
    for field in parsed.fields:
        if (
            field.number == field_number
            and field.wire_type == 5
            and isinstance(field.value, int)
        ):
            return field.value
    return None


def _parse_part_colors(
    parsed: ProtobufParseResult, field_number: int
) -> tuple[list[dict[str, int | None]], list[str]]:
    colors: list[dict[str, int | None]] = []
    errors: list[str] = []
    for index, raw_color in enumerate(protobuf_bytes(parsed, field_number)):
        color = parse_protobuf(raw_color)
        if not color.complete:
            errors.append(
                f"field {field_number} color {index}: {color.error}"
            )
            continue
        colors.append(
            {
                "plate_index": _first_varint(color, 1),
                "color_index": _first_varint(color, 2),
            }
        )
    return colors, errors


def _parse_fashion_detail(
    data: bytes,
) -> tuple[dict[str, Any] | None, list[str]]:
    parsed = parse_protobuf(data)
    fashion_index = _first_varint(parsed, 1)
    if fashion_index is None:
        return None, [parsed.error or "fashion_detail has no fashion_index"]
    errors = [parsed.error] if parsed.error else []
    part_colors, color_errors = _parse_part_colors(parsed, 2)
    extra_colors, extra_color_errors = _parse_part_colors(parsed, 9)
    part_colors_right, right_color_errors = _parse_part_colors(parsed, 23)
    errors.extend(color_errors)
    errors.extend(extra_color_errors)
    errors.extend(right_color_errors)
    count = _first_varint(parsed, 5)
    transparency_bits = _first_fixed32(parsed, 22)
    detail = {
        "fashion_index": fashion_index,
        "kind": "standard",
        "entry_present": True,
        "owned": True,
        "count": count,
        "ui_owned": count > 0 if count is not None else None,
        "unlocked_plate_count": _first_varint(parsed, 3),
        "unlocked_plate_mask": _first_varint(parsed, 4),
        "modeling_unlock_mask": _first_varint(parsed, 7),
        "modeling_now": _first_varint(parsed, 8),
        "evolution": _first_varint(parsed, 10, 0),
        "order": _first_varint(parsed, 11, 0),
        "extra_model_data": list(_repeated_int32(parsed, 12)),
        "gradient_color_count": len(protobuf_bytes(parsed, 13)),
        "gradient_time": _first_varint(parsed, 14),
        "gradient_switch": bool(_first_varint(parsed, 15, 0)),
        "channel_count": list(_repeated_int32(parsed, 16)),
        "current_color_scheme_index": _first_varint(parsed, 17, -1),
        "color_scheme_count": len(protobuf_bytes(parsed, 18)),
        "with_scheme": bool(_first_varint(parsed, 19, 0)),
        "transparency": (
            struct.unpack("<f", transparency_bits.to_bytes(4, "little"))[0]
            if transparency_bits is not None
            else None
        ),
        "part_colors": part_colors,
        "extra_unlocked_colors": extra_colors,
        "part_colors_right": part_colors_right,
        "observed_fields": sorted({field.number for field in parsed.fields}),
        "unknown_fields": sorted(
            {field.number for field in parsed.fields if field.number > 25}
        ),
    }
    return detail, errors


def _parse_diy_fashion_detail(
    data: bytes,
) -> tuple[dict[str, Any] | None, str | None]:
    parsed = parse_protobuf(data)
    fashion_id = _first_varint(parsed, 3)
    if fashion_id is None:
        return None, parsed.error or "diy_fashion_detail has no fashion_id"
    return (
        {
            "fashion_index": fashion_id | 0x40000000,
            "diy_fashion_id": fashion_id,
            "kind": "diy_instance",
            "entry_present": True,
            "owned": True,
            "count": 1,
            "ui_owned": True,
            "review_state": _first_varint(parsed, 9),
            "observed_fields": sorted({field.number for field in parsed.fields}),
            "unknown_fields": sorted(
                {field.number for field in parsed.fields if field.number > 11}
            ),
        },
        parsed.error,
    )


def _analyze_wardrobe(
    messages: list[GameMessage],
    wardrobe_ack_cursors: dict[
        tuple[str | None, int | None] | int, list[int]
    ]
    | None = None,
) -> dict[str, Any]:
    wardrobe_ack_cursors = wardrobe_ack_cursors or {}
    wardrobe_messages = [
        message
        for message in messages
        if message.command_id
        in {
            GP_FASHION_INFO,
            GP_ACTIVE_FASHION,
            GP_FASHION_EXPIRE,
            GP_FASHION_RENEW,
            GP_DIY_FASHION_DATA,
            GP_FASHION_OBTAIN_SUIT,
        }
    ]
    parse_errors: list[str] = []
    indexed_messages = list(enumerate(messages))
    batches: list[dict[str, Any]] = []
    pending_by_connection: dict[
        tuple[str | None, int | None], dict[str, Any]
    ] = {}
    snapshot_messages = 0

    for ordinal, message in indexed_messages:
        if message.command_id != GP_FASHION_INFO:
            continue
        snapshot_messages += 1
        parsed = parse_protobuf(message.payload)
        current_details = protobuf_bytes(parsed, 2)
        detail_field = 2 if current_details else 4
        raw_details = current_details or protobuf_bytes(parsed, 4)
        connection_key = (message.capture_id, message.stream_id)
        batch = pending_by_connection.setdefault(
            connection_key,
            {
                "capture_id": message.capture_id,
                "stream_id": message.stream_id,
                "fashions": {},
                "fragments": 0,
                "complete": True,
                "start_ordinal": ordinal,
                "sources": set(),
                "schema_revision": (
                    "current_field2" if detail_field == 2 else "legacy_field4"
                ),
            },
        )
        batch["fragments"] += 1
        batch["sources"].add(message.source)
        if not parsed.complete:
            batch["complete"] = False
            parse_errors.append(
                f"gp_fashion_info at {message.frame_offset}: {parsed.error}"
            )
        for detail_index, raw_detail in enumerate(raw_details):
            detail, detail_errors = _parse_fashion_detail(raw_detail)
            for detail_error in detail_errors:
                parse_errors.append(
                    "gp_fashion_info detail "
                    f"{detail_index} at {message.frame_offset}: {detail_error}"
                )
                batch["complete"] = False
            if detail is not None:
                detail["source_command"] = GP_FASHION_INFO
                detail["source_frame_offset"] = message.frame_offset
                detail["stream_id"] = message.stream_id
                batch["fashions"][detail["fashion_index"]] = detail
        cursor_values = protobuf_varints(parsed, 32)
        cursor = _signed_int32(cursor_values[0]) if cursor_values else 0
        batch["last_cursor"] = cursor
        batch["cursor_explicit"] = bool(cursor_values)
        if cursor == 0:
            batch["end_ordinal"] = ordinal
            batch["terminal_cursor_seen"] = True
            batches.append(batch)
            pending_by_connection.pop(connection_key, None)

    selected_batch = next(
        (batch for batch in reversed(batches) if batch["complete"]), None
    )
    fashions: dict[int, dict[str, Any]] = (
        dict(selected_batch["fashions"]) if selected_batch else {}
    )
    incremental_indices: set[int] = set()
    delta_events: list[dict[str, Any]] = []
    partial_fashion_indices: set[int] = set()
    if selected_batch is None:
        state_is_partial = bool(pending_by_connection or batches)
    else:
        state_is_partial = any(
            batch["start_ordinal"] > selected_batch["end_ordinal"]
            for batch in pending_by_connection.values()
        ) or any(
            not batch["complete"]
            and batch["end_ordinal"] > selected_batch["end_ordinal"]
            for batch in batches
        )
    complete_incremental_messages = 0
    incremental_messages = 0

    if selected_batch is not None:
        for ordinal, message in indexed_messages:
            if (
                ordinal <= selected_batch["end_ordinal"]
                or (
                    message.capture_id,
                    message.stream_id,
                )
                != (
                    selected_batch["capture_id"],
                    selected_batch["stream_id"],
                )
                or message.command_id
                not in {
                    GP_ACTIVE_FASHION,
                    GP_FASHION_EXPIRE,
                    GP_FASHION_RENEW,
                    GP_FASHION_OBTAIN_SUIT,
                }
            ):
                continue
            incremental_messages += 1
            parsed = parse_protobuf(message.payload)
            if message.command_id == GP_FASHION_EXPIRE:
                index = _first_varint(parsed, 2)
                delta_events.append(
                    {
                        "command_id": message.command_id,
                        "operation": "expire_candidate",
                        "fashion_index": index,
                        "frame_offset": message.frame_offset,
                    }
                )
                if index is not None:
                    partial_fashion_indices.add(index)
                state_is_partial = True
                continue
            detail_field = (
                4 if message.command_id == GP_FASHION_OBTAIN_SUIT else 2
            )
            if (
                message.command_id == GP_FASHION_OBTAIN_SUIT
                and (_first_varint(parsed, 2, 0) or 0) != 0
            ):
                continue
            details: list[dict[str, Any]] = []
            detail_failed = not parsed.complete
            for raw_detail in protobuf_bytes(parsed, detail_field):
                detail, detail_errors = _parse_fashion_detail(raw_detail)
                detail_failed = detail_failed or bool(detail_errors)
                if detail is not None:
                    detail["source_command"] = message.command_id
                    detail["source_frame_offset"] = message.frame_offset
                    detail["stream_id"] = message.stream_id
                    details.append(detail)
                for detail_error in detail_errors:
                    parse_errors.append(
                        f"command {message.command_id} detail at "
                        f"{message.frame_offset}: {detail_error}"
                    )
            if detail_failed or not details:
                state_is_partial = True
                partial_fashion_indices.update(
                    detail["fashion_index"] for detail in details
                )
                continue
            complete_incremental_messages += 1
            for detail in details:
                old_count = (
                    fashions.get(detail["fashion_index"], {}).get("count")
                )
                fashions[detail["fashion_index"]] = detail
                incremental_indices.add(detail["fashion_index"])
                delta_events.append(
                    {
                        "command_id": message.command_id,
                        "operation": "upsert",
                        "fashion_index": detail["fashion_index"],
                        "old_count": old_count,
                        "new_count": detail.get("count"),
                        "frame_offset": message.frame_offset,
                    }
                )

    standard_state_is_partial = state_is_partial
    diy_snapshot_messages = 0
    diy_snapshot_observed = False
    diy_status = "unobserved"
    diy_entries: dict[int, dict[str, Any]] = {}
    if selected_batch is not None:
        diy_candidates = [
            message
            for message in messages
            if message.command_id == GP_DIY_FASHION_DATA
            and (
                message.capture_id,
                message.stream_id,
            )
            == (
                selected_batch["capture_id"],
                selected_batch["stream_id"],
            )
        ]
        diy_snapshot_messages = len(diy_candidates)
        if diy_candidates:
            diy_message = diy_candidates[-1]
            diy_parsed = parse_protobuf(diy_message.payload)
            diy_failed = not diy_parsed.complete
            for raw_detail in protobuf_bytes(diy_parsed, 2):
                detail, error = _parse_diy_fashion_detail(raw_detail)
                if error:
                    diy_failed = True
                    parse_errors.append(
                        f"gp_diy_fashion_data at {diy_message.frame_offset}: {error}"
                    )
                if detail is not None:
                    detail["source_command"] = GP_DIY_FASHION_DATA
                    detail["source_frame_offset"] = diy_message.frame_offset
                    detail["stream_id"] = diy_message.stream_id
                    diy_entries[detail["fashion_index"]] = detail
            if not diy_failed:
                diy_snapshot_observed = True
                fashions.update(diy_entries)
                diy_status = (
                    "observed_present" if diy_entries else "observed_absent"
                )
            else:
                state_is_partial = True
                diy_status = "partial"

    snapshot_observed = selected_batch is not None
    if state_is_partial:
        status = "partial"
    elif snapshot_observed:
        status = "observed_present" if fashions else "observed_absent"
    elif wardrobe_messages:
        status = "partial"
    else:
        status = "unobserved"

    selected_capture = selected_batch["capture_id"] if selected_batch else None
    selected_stream = selected_batch["stream_id"] if selected_batch else None
    selected_connection = (selected_capture, selected_stream)
    ack_cursors = wardrobe_ack_cursors.get(selected_connection, [])
    if not ack_cursors and selected_capture is None and selected_stream is not None:
        # Backward-compatible unit/programmatic callers without capture identity.
        ack_cursors = wardrobe_ack_cursors.get(selected_stream, [])
    terminal_ack_seen = 0 in ack_cursors
    if selected_batch is None:
        evidence_messages = wardrobe_messages
    else:
        evidence_messages = [
            message
            for message in wardrobe_messages
            if (message.capture_id, message.stream_id)
            == selected_connection
        ]
    evidence = _evidence_metadata(evidence_messages)
    if snapshot_observed and terminal_ack_seen:
        evidence = {
            "evidence_level": "corroborated",
            "evidence_sources": sorted(
                set(evidence["evidence_sources"]) | {"client_ack_143"}
            ),
        }
    return {
        **evidence,
        "status": status,
        "snapshot_observed": snapshot_observed,
        "snapshot_complete": snapshot_observed and not state_is_partial,
        "standard_wardrobe_complete": (
            snapshot_observed
            and terminal_ack_seen
            and not standard_state_is_partial
        ),
        "full_wardrobe_complete": (
            snapshot_observed
            and diy_snapshot_observed
            and terminal_ack_seen
            and not state_is_partial
        ),
        "snapshot_messages": snapshot_messages,
        "complete_snapshot_messages": sum(
            1 for batch in batches if batch["complete"]
        ),
        "snapshot_capture_id": selected_capture,
        "snapshot_stream_id": selected_stream,
        "snapshot_fragments": selected_batch["fragments"] if selected_batch else 0,
        "snapshot_schema_revision": (
            selected_batch["schema_revision"] if selected_batch else None
        ),
        "terminal_cursor_seen": bool(selected_batch),
        "terminal_ack_seen": terminal_ack_seen,
        "ack_cursors": ack_cursors,
        "incremental_messages": incremental_messages,
        "complete_incremental_messages": complete_incremental_messages,
        "fashion_count": len(fashions),
        "standard_fashion_count": sum(
            item.get("kind") == "standard" for item in fashions.values()
        ),
        "diy_fashion_count": sum(
            item.get("kind") == "diy_instance" for item in fashions.values()
        ),
        "diy_snapshot_messages": diy_snapshot_messages,
        "diy_snapshot_observed": diy_snapshot_observed,
        "diy_status": diy_status,
        "coverage": {
            "standard_fashion": snapshot_observed,
            "diy_fashion": diy_snapshot_observed,
        },
        "fashions": [fashions[index] for index in sorted(fashions)],
        "incremental_fashion_indices": sorted(incremental_indices),
        "partial_fashion_indices": sorted(partial_fashion_indices),
        "deltas": delta_events,
        "parse_errors": parse_errors,
        "semantics": (
            "A terminal gp_fashion_info batch supports the standard owned-key "
            "list. Entry presence and count-based UI ownership are reported "
            "separately. DIY instances require gp_diy_fashion_data. Unknown or "
            "partial messages never turn unobserved IDs into absent items."
        ),
    }


def _parse_pool_info(data: bytes) -> tuple[dict[str, Any] | None, str | None]:
    parsed = parse_protobuf(data)
    pool_id = _first_varint(parsed, 1)
    if pool_id is None:
        return None, parsed.error or "pool_info has no id"
    return (
        {
            "id": pool_id,
            "free_cnt": _first_varint(parsed, 2),
            "next_free_timestamp": _first_varint(parsed, 3),
            "daily_left_cnt": _first_varint(parsed, 4),
            "amount": _first_varint(parsed, 5),
        },
        parsed.error,
    )


def _normalize_pool_catalog(
    lottery_catalog: dict[str, Any] | None,
) -> dict[str, list[str]]:
    if not lottery_catalog:
        return {}
    if isinstance(lottery_catalog.get("pool_id_to_key"), dict):
        raw = lottery_catalog["pool_id_to_key"]
    elif isinstance(lottery_catalog.get("mapping"), dict):
        raw = lottery_catalog["mapping"]
    elif isinstance(lottery_catalog.get("pools"), list):
        normalized: dict[str, list[str]] = {}
        for entry in lottery_catalog["pools"]:
            if not isinstance(entry, dict):
                continue
            pool_id = entry.get(
                "lottery_pool_id", entry.get("pool_id", entry.get("id"))
            )
            keys = entry.get("keys") or entry.get("pool_keys") or entry.get("key") or entry.get("pool_key")
            if pool_id is None or keys is None:
                continue
            if isinstance(keys, (str, int)):
                keys = [keys]
            target = normalized.setdefault(str(pool_id), [])
            for key in keys:
                value = str(key)
                if value not in target:
                    target.append(value)
        return normalized
    elif isinstance(lottery_catalog, dict):
        raw = lottery_catalog
    else:
        return {}

    normalized: dict[str, list[str]] = {}
    for pool_id, key in raw.items():
        if key is None:
            continue
        values = key if isinstance(key, list) else [key]
        normalized[str(pool_id)] = [str(value) for value in values]
    return normalized


def _normalize_photo_catalog(
    photo_catalog: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    if not photo_catalog:
        return {}
    # v3 pool catalog maps real scene IDs to background keys; never infer IDs from bgN.
    if isinstance(photo_catalog.get("pools"), list):
        normalized: dict[str, dict[str, Any]] = {}
        for entry in photo_catalog["pools"]:
            if not isinstance(entry, dict):
                continue
            kind = str(entry.get("att_type", entry.get("attType", entry.get("pool_type", entry.get("type", entry.get("kind", "")))))).lower()
            if kind not in {"attbg", "background", "bg"}:
                continue
            scene_ids = entry.get("scene_ids") or []
            if not isinstance(scene_ids, list):
                continue
            key = entry.get("key") or entry.get("pool_key") or entry.get("name")
            for scene_id in scene_ids:
                normalized[str(scene_id)] = {"key": key, "name": entry.get("name")}
        return normalized
    raw = photo_catalog
    if isinstance(photo_catalog.get("records"), list):
        raw = {
            item.get("key", item.get("id")): item
            for item in photo_catalog["records"]
            if isinstance(item, dict)
        }
    normalized: dict[str, dict[str, Any]] = {}
    for key, value in raw.items():
        if value is None:
            continue
        candidate: dict[str, Any]
        if isinstance(value, dict):
            candidate = dict(value)
        else:
            candidate = {"name": str(value)}
        photo_id = str(key)
        if photo_id.isdigit():
            normalized[photo_id] = candidate
    return normalized


def _analyze_photo_info(
    messages: list[GameMessage],
    photo_catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    responses = [m for m in messages if m.command_id == GP_PHOTO_INFO]
    records: list[dict[str, Any]] = []
    parse_errors: list[str] = []
    complete_frames = 0
    error_frames = 0
    background_catalog = _normalize_photo_catalog(photo_catalog)
    background_catalog_match_count = 0
    photo_ids_without_catalog: set[int] = set()
    for message in responses:
        parsed = parse_protobuf(message.payload)
        error_code = _first_varint(parsed, 3)
        if error_code not in (None, 0) and not protobuf_bytes(parsed, 3):
            error_frames += 1
        if parsed.complete:
            complete_frames += 1
        if parsed.error:
            parse_errors.append(f"gp_photo_info at {message.frame_offset}: {parsed.error}")
        partial_flag = _first_varint(parsed, 4)
        frame: dict[str, Any] = {
            "frame_offset": message.frame_offset,
            "field4": partial_flag,
            "field2_photo_info": [],
            "field3_photo_info": [],
            "photo_ids": [],
            "photo_decos": [],
            "complete": parsed.complete,
            "partial_flag": 0 if partial_flag is None else partial_flag,
        }
        for number in (2, 3):
            raw_values = protobuf_bytes(parsed, number)
            frame[f"raw_field{number}"] = [value.hex() for value in raw_values]
            for raw in raw_values:
                nested = parse_protobuf(raw)
                photo_id = _first_varint(nested, 1)
                photo_match = background_catalog.get(str(photo_id)) if (number == 2 and photo_id is not None) else None
                if number == 2 and photo_match is None and photo_id is not None:
                    photo_ids_without_catalog.add(photo_id)
                elif number == 2 and photo_match is not None:
                    background_catalog_match_count += 1
                frame[f"field{number}_photo_info"].append({
                    "raw": raw.hex(),
                    "complete": nested.complete,
                    "observed_fields": sorted({f.number for f in nested.fields}),
                    "id": photo_id,
                    "timestamp": _first_varint(nested, 2),
                    "background_catalog_match": (
                        {
                            "key": photo_match.get("key"),
                            "name": (
                                photo_match.get("name")
                                or (photo_match.get("texts") or [None])[0]
                            ),
                            "score": (
                                photo_match.get("score")
                                or photo_match.get("best_score")
                                or (photo_match.get("scores") or [None])[0]
                            ),
                        }
                        if number == 2 and photo_match
                        else None
                    ),
                })
                frame["photo_ids" if number == 2 else "photo_decos"].append(
                    frame[f"field{number}_photo_info"][-1]
                )
                if not nested.complete:
                    frame["complete"] = False
                if nested.error:
                    parse_errors.append(f"gp_photo_info field {number} at {message.frame_offset}: {nested.error}")
        records.append(frame)
    observed_frames = len(responses)
    has_partial = any(not frame["complete"] or frame.get("partial_flag") for frame in records)
    return {
        **_evidence_metadata(responses),
        "status": "unobserved" if not responses else ("observed_error" if error_frames == observed_frames else ("partial" if has_partial or complete_frames != observed_frames or error_frames else "observed_present")),
        "observed_frames": observed_frames,
        "complete_frames": complete_frames,
        "error_frames": error_frames,
        "frame_count": observed_frames,
        "field2_count": sum(len(r["field2_photo_info"]) for r in records),
        "field3_count": sum(len(r["field3_photo_info"]) for r in records),
        "count": sum(len(r["field2_photo_info"]) + len(r["field3_photo_info"]) for r in records),
        "background_catalog": {
            "status": "loaded" if background_catalog else "unavailable",
            "matched_records": background_catalog_match_count,
            "unmapped_ids": sorted(photo_ids_without_catalog),
            "catalog_size": len(background_catalog),
        },
        "completeness": bool(responses) and not has_partial and not error_frames and complete_frames == observed_frames,
        "partial_flag": 1 if has_partial or error_frames or complete_frames != observed_frames else 0,
        "records": records,
        "parse_errors": parse_errors,
        "semantics": (
            "仅报告命令637中观察到的原始field2/field3及可直接读取的ID/timestamp；"
            "当提供背景目录时同时尝试输出对应背景映射，未匹配的仍保持unknown。"
        ),
    }


def _analyze_lottery(
    messages: list[GameMessage],
    lottery_catalog: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    responses = [
        message
        for message in messages
        if message.command_id == GP_LUCKYDRAW_OPERATE_RE
    ]
    draw_response_messages: list[GameMessage] = []
    pools: dict[int, dict[str, Any]] = {}
    draw_events: list[dict[str, Any]] = []
    parse_errors: list[str] = []
    snapshot_observed = False
    pool_state_is_partial = False
    draw_state_is_partial = False
    duplicate_pool_ids: set[int] = set()
    partial_response_messages = 0
    error_response_messages = 0
    draw_error_response_messages = 0

    for message in responses:
        parsed = parse_protobuf(message.payload)
        op_type = _first_varint(parsed, 2)
        if op_type in {2, 4}:
            draw_response_messages.append(message)
        if not parsed.complete:
            partial_response_messages += 1
            pool_state_is_partial = True
            if op_type in {2, 4}:
                draw_state_is_partial = True
            parse_errors.append(
                f"gp_luckydraw_operate_re at {message.frame_offset}: {parsed.error}"
            )
            continue
        if (_first_varint(parsed, 3, 0) or 0) != 0:
            error_response_messages += 1
            if op_type in {2, 4}:
                draw_error_response_messages += 1
            continue

        parsed_pools: list[dict[str, Any]] = []
        nested_pool_error = False
        for raw_pool in protobuf_bytes(parsed, 7):
            pool, error = _parse_pool_info(raw_pool)
            if error:
                nested_pool_error = True
                parse_errors.append(
                    f"lottery pool_info at {message.frame_offset}: {error}"
                )
            if pool is not None and error is None:
                parsed_pools.append(pool)

        if op_type == 1:
            if nested_pool_error:
                pool_state_is_partial = True
            else:
                pools = {}
                for pool in parsed_pools:
                    if pool["id"] in pools:
                        duplicate_pool_ids.add(pool["id"])
                        pool_state_is_partial = True
                        continue
                    pools[pool["id"]] = pool
                snapshot_observed = True
                if not duplicate_pool_ids:
                    pool_state_is_partial = False
        elif parsed_pools:
            for pool in parsed_pools:
                pools[pool["id"]] = pool
            if nested_pool_error:
                pool_state_is_partial = True

        if op_type in {2, 4}:
            values = _repeated_int32(parsed, 6)
            requested_count = _first_varint(parsed, 5, 0) or 0
            if (
                nested_pool_error
                or requested_count <= 0
                or len(values) != requested_count * 2
            ):
                draw_state_is_partial = True
                parse_errors.append(
                    f"lottery draw at {message.frame_offset}: expected "
                    f"{requested_count * 2} result values, got {len(values)}"
                )
                continue
            results = [
                {"type": values[index], "id": values[index + 1]}
                for index in range(0, len(values) - 1, 2)
            ]
            draw_events.append(
                {
                    "pool_order": _first_varint(parsed, 4),
                    "count": requested_count,
                    "results": results,
                    "proxy": op_type == 4,
                    "proxy_player_id": _first_varint(parsed, 9),
                }
            )

    if pool_state_is_partial:
        pool_status = "partial"
    elif snapshot_observed:
        pool_status = "observed_present" if pools else "observed_absent"
    elif pools:
        pool_status = "partial"
    elif responses and error_response_messages == len(responses):
        pool_status = "observed_error"
    else:
        pool_status = "unobserved"
    historical_counts = {
        str(pool_id): int(pool["amount"])
        for pool_id, pool in sorted(pools.items())
        if isinstance(pool.get("amount"), int)
    }
    normalized_catalog = _normalize_pool_catalog(lottery_catalog)
    by_pool_key: dict[str, int] = {}
    unmapped_by_pool_id: dict[str, int] = {}
    for pool_id, amount in historical_counts.items():
        pool_keys = normalized_catalog.get(pool_id)
        if pool_keys is None:
            unmapped_by_pool_id[pool_id] = amount
            continue
        for pool_key in pool_keys:
            by_pool_key[pool_key] = amount
    historical_snapshot_complete = (
        snapshot_observed and not duplicate_pool_ids and len(historical_counts) == len(pools)
    )
    if pool_state_is_partial and responses:
        draw_status = "partial"
    elif historical_snapshot_complete:
        draw_status = "observed_present" if historical_counts else "observed_absent"
    elif responses and error_response_messages == len(responses):
        draw_status = "observed_error"
    elif draw_state_is_partial:
        draw_status = "partial"
    else:
        draw_status = "observed_present" if draw_events else "unobserved"
    captured_draw_count = (
        sum(event["count"] for event in draw_events) if draw_events else None
    )
    if draw_state_is_partial:
        history_status = "partial"
    elif draw_events:
        history_status = "observed_present"
    elif (
        draw_response_messages
        and draw_error_response_messages == len(draw_response_messages)
    ):
        history_status = "observed_error"
    else:
        history_status = "unobserved"
    pool_evidence = _evidence_metadata(responses)
    draw_evidence = _evidence_metadata(draw_response_messages)
    draw_count_evidence = pool_evidence if historical_snapshot_complete else draw_evidence
    return {
        "draw_count": {
            **draw_count_evidence,
            "status": draw_status,
            "value": None,
            "by_pool_id": historical_counts,
            "by_pool_key": by_pool_key,
            "unmapped_by_pool_id": unmapped_by_pool_id,
            "observed_pool_count": len(historical_counts),
            "snapshot_complete": historical_snapshot_complete,
            "captured_draw_count": captured_draw_count,
            "scope": (
                "server_pool_snapshot"
                if historical_snapshot_complete
                else "capture_only"
            ),
            "evidence_messages": (
                len(responses) if historical_snapshot_complete else len(draw_events)
            ),
            "source_field": (
                "gp_luckydraw_operate_re.pool_info.amount (protobuf field 5)"
                if historical_snapshot_complete
                else None
            ),
            "pool_id_to_key_catalog": {
                "status": "loaded" if normalized_catalog else "unavailable",
                "mapped_pool_count": len(by_pool_key),
                "unmapped_pool_count": len(unmapped_by_pool_id),
            },
            "duplicate_pool_ids": sorted(duplicate_pool_ids),
            "completeness": historical_snapshot_complete,
            "semantics": (
                "Each by_pool_id value is the server-reported cumulative draw "
                "amount for that lottery pool. Pool IDs still require a "
                "version-matched catalog before they can be assigned to "
                "mini-program pool keys."
                if historical_snapshot_complete
                else "No cumulative pool amount or draw response was observed; "
                "this does not mean zero draws."
            ),
        },
        "gacha_history": {
            **draw_evidence,
            "status": history_status,
            "scope": "capture_only",
            "entries": draw_events,
            "semantics": (
                "The protocol exposes draw results observed during capture; it "
                "does not prove a complete historical ledger."
            ),
        },
        "pool_presence": {
            **pool_evidence,
            "status": pool_status,
            "snapshot_observed": snapshot_observed,
            "response_messages": len(responses),
            "partial_response_messages": partial_response_messages,
            "error_response_messages": error_response_messages,
            "pools": [pools[pool_id] for pool_id in sorted(pools)],
            "parse_errors": parse_errors,
            "duplicate_pool_ids": sorted(duplicate_pool_ids),
            "completeness": snapshot_observed and not pool_state_is_partial and not duplicate_pool_ids,
            "semantics": "Unobserved pools are never reported as absent.",
        },
    }


def analyze_game_messages(
    messages: Iterable[GameMessage],
    *,
    wardrobe_ack_cursors: dict[
        tuple[str | None, int | None] | int, list[int]
    ]
    | None = None,
    lottery_catalog: dict[str, str] | dict[str, Any] | None = None,
    photo_catalog: dict[str, str] | dict[str, Any] | None = None,
) -> dict[str, Any]:
    message_list = list(messages)
    by_id: dict[int, int] = defaultdict(int)
    for message in message_list:
        by_id[message.command_id] += 1
    lottery = _analyze_lottery(message_list, lottery_catalog=lottery_catalog)
    photo_info = _analyze_photo_info(message_list, photo_catalog=photo_catalog)
    return {
        "game_message_counts": {
            str(command_id): by_id[command_id] for command_id in sorted(by_id)
        },
        "data_coverage": {
            "draw_count": lottery["draw_count"],
            "gacha_history": lottery["gacha_history"],
            "pool_presence": lottery["pool_presence"],
            "photo_info": photo_info,
            "wardrobe_presence": _analyze_wardrobe(
                message_list, wardrobe_ack_cursors
            ),
        },
    }
