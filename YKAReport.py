from __future__ import annotations

import hashlib
import json
import stat
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from YKABusiness import (
    GP_ACTIVE_FASHION,
    GP_DIY_FASHION_DATA,
    GP_FASHION_EXPIRE,
    GP_FASHION_INFO_ACK,
    GP_FASHION_INFO,
    GP_FASHION_OBTAIN_SUIT,
    GP_FASHION_RENEW,
    GP_LUCKYDRAW_OPERATE_RE,
    GP_PHOTO_INFO,
    TARGET_GAME_MESSAGE_IDS,
    analyze_game_messages,
)
from YKACatalog import CatalogDecodeError, load_fashion_catalog
from YKACore import (
    RUNTIME_DIR,
    SESSIONS_DIR,
    atomic_write_json,
    now_iso,
    read_json,
)
from YKAProtocol import (
    PartialCompactFrame,
    ProtocolDecodeError,
    count_capture_protocols,
    decode_capture_set,
    iter_game_messages,
    parse_protobuf,
    protobuf_varints,
    read_compact_uint,
)


WARDROBE_GAME_MESSAGE_IDS = {
    GP_FASHION_INFO,
    GP_ACTIVE_FASHION,
    GP_FASHION_EXPIRE,
    GP_FASHION_RENEW,
    GP_DIY_FASHION_DATA,
    GP_FASHION_OBTAIN_SUIT,
}

REPORT_FILENAME = "report.json"
WECHAT_EXPORT_FILENAME = "wechat-export.json"
CAPTURE_CLEANUP_FILENAME = "capture-cleanup.json"
_REPORT_BUILD_LOCK = threading.Lock()


def _read_events(path: Path) -> tuple[list[dict[str, Any]], int]:
    events: list[dict[str, Any]] = []
    parse_errors = 0
    if not path.exists():
        return events, parse_errors
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if isinstance(value, dict):
                events.append(value)
    return events, parse_errors


def _protocol_counts(pcap_files: list[Path]) -> tuple[Counter[str], list[str]]:
    if not pcap_files:
        return Counter(), []
    try:
        return count_capture_protocols(pcap_files), []
    except ProtocolDecodeError as error:
        return Counter(), [str(error)]


def _partial_gamedata_command(
    partial: PartialCompactFrame,
) -> int | None:
    if partial.type_id != 34:
        return None
    try:
        data_length, payload_offset = read_compact_uint(partial.payload, 0)
    except (EOFError, ProtocolDecodeError):
        return None
    if data_length < 2:
        return None
    if payload_offset + data_length != partial.declared_length:
        return None
    command_end = payload_offset + 2
    if command_end > len(partial.payload):
        return None
    return int.from_bytes(partial.payload[payload_offset:command_end], "little")


def _decode_game_traffic(
    pcap_files: list[Path],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    outer_counts: Counter[int] = Counter()
    streams_summary: list[dict[str, Any]] = []
    partial_frames: list[dict[str, Any]] = []
    messages = []
    errors: list[str] = []
    partial_targets: list[tuple[str, int, int | None]] = []
    candidate_message_counts: Counter[int] = Counter()
    direct_message_counts: Counter[int] = Counter()
    client_outer_counts: Counter[int] = Counter()
    client_candidate_counts: Counter[int] = Counter()
    client_streams_summary: list[dict[str, Any]] = []
    wardrobe_ack_cursors: dict[tuple[str, int], list[int]] = defaultdict(list)

    source_pcaps = list(pcap_files)
    source_paths = [str(path) for path in source_pcaps]
    pcap_label = source_paths[0] if len(source_paths) == 1 else f"<capture set: {len(source_paths)} files>"
    identity_source = "\0".join(str(path.resolve()) for path in source_pcaps)
    capture_id = "capture-set:" + hashlib.sha256(identity_source.encode("utf-8")).hexdigest()[:16]
    try:
        streams, client_streams, _native_protocol_counts = decode_capture_set(source_pcaps)
    except ProtocolDecodeError as error:
        errors.append(f"{pcap_label}: {error}")
        streams, client_streams = (), ()
    for stream in streams:
            outer_counts.update(frame.type_id for frame in stream.frames)
            stream_messages = list(
                iter_game_messages(
                    stream,
                    direct_ids=TARGET_GAME_MESSAGE_IDS,
                    capture_id=capture_id,
                )
            )
            stream_candidate_messages = [
                message
                for message in stream_messages
                if message.source == "gamedata_candidate"
            ]
            stream_direct_messages = [
                message for message in stream_messages if message.source == "direct"
            ]
            candidate_message_counts.update(
                message.command_id for message in stream_candidate_messages
            )
            direct_message_counts.update(
                message.command_id for message in stream_direct_messages
            )
            messages.extend(stream_messages)
            summary = {
                "pcap": pcap_label,
                "source_pcaps": source_paths,
                "capture_id": capture_id,
                "tcp_stream": stream.reassembly.stream_id,
                "tcp_segments": stream.reassembly.segment_count,
                "tcp_payload_bytes": len(stream.reassembly.payload),
                "tcp_gap_bytes": stream.reassembly.gap_bytes,
                "tcp_conflict_bytes": stream.reassembly.conflict_bytes,
                "transport_mode": stream.transport_mode,
                "plaintext_bytes": stream.plaintext_bytes,
                "compressed_bytes": stream.compressed_bytes,
                "decompressed_bytes": stream.decompressed_bytes,
                "mppc_blocks": stream.mppc_blocks,
                "complete_frames": len(stream.frames),
                "candidate_game_messages": len(stream_candidate_messages),
                "nested_candidate_game_messages": 0,
                "direct_game_messages": len(stream_direct_messages),
                "decode_error": stream.decode_error,
            }
            streams_summary.append(summary)
            if stream.decode_error:
                errors.append(
                    f"{pcap_label} stream {stream.reassembly.stream_id}: "
                    f"{stream.decode_error}"
                )
            if stream.partial_frame is not None:
                partial = stream.partial_frame
                inferred_command = (
                    _partial_gamedata_command(partial)
                    if partial.type_id == 34
                    else (
                        partial.type_id
                        if partial.type_id in TARGET_GAME_MESSAGE_IDS
                        else None
                    )
                )
                partial_frames.append(
                    {
                        "pcap": pcap_label,
                        "source_pcaps": source_paths,
                        "capture_id": capture_id,
                        "tcp_stream": stream.reassembly.stream_id,
                        "type_id": partial.type_id,
                        "declared_bytes": partial.declared_length,
                        "captured_bytes": len(partial.payload),
                        "transport": partial.transport,
                        "inferred_command_id": inferred_command,
                    }
                )
                if partial.type_id == 34 or inferred_command is not None:
                    partial_targets.append(
                        (
                            capture_id,
                            stream.reassembly.stream_id,
                            inferred_command,
                        )
                    )
    for stream in client_streams:
        client_outer_counts.update(frame.type_id for frame in stream.frames)
        client_messages = list(iter_game_messages(stream, capture_id=capture_id))
        client_candidate_counts.update(message.command_id for message in client_messages)
        for message in client_messages:
            if message.command_id != GP_FASHION_INFO_ACK:
                continue
            parsed_ack = parse_protobuf(message.payload)
            cursors = protobuf_varints(parsed_ack, 2)
            if parsed_ack.complete and cursors:
                wardrobe_ack_cursors[(capture_id, stream.reassembly.stream_id)].append(int(cursors[0]))
        client_streams_summary.append(
            {
                "pcap": pcap_label,
                "source_pcaps": source_paths,
                "capture_id": capture_id,
                "tcp_stream": stream.reassembly.stream_id,
                "tcp_segments": stream.reassembly.segment_count,
                "tcp_payload_bytes": len(stream.reassembly.payload),
                "tcp_gap_bytes": stream.reassembly.gap_bytes,
                "tcp_conflict_bytes": stream.reassembly.conflict_bytes,
                "transport_mode": stream.transport_mode,
                "complete_frames": len(stream.frames),
                "candidate_game_messages": len(client_messages),
                "decode_error": stream.decode_error,
            }
        )
        if stream.decode_error:
            errors.append(
                f"{pcap_label} client stream "
                f"{stream.reassembly.stream_id}: {stream.decode_error}"
            )

    business = analyze_game_messages(
        messages,
        wardrobe_ack_cursors=dict(wardrobe_ack_cursors),
        lottery_catalog=_load_lottery_pool_catalog(),
        photo_catalog=_load_photo_catalog(),
    )
    data_coverage = business["data_coverage"]
    wardrobe = data_coverage["wardrobe_presence"]
    selected_wardrobe_connection = (
        wardrobe.get("snapshot_capture_id"),
        wardrobe.get("snapshot_stream_id"),
    )
    partial_wardrobe_connections = {
        (capture_id, stream_id)
        for capture_id, stream_id, command_id in partial_targets
        if command_id is None or command_id in WARDROBE_GAME_MESSAGE_IDS
    }
    relevant_wardrobe_partial = bool(partial_wardrobe_connections) and (
        not wardrobe.get("snapshot_observed")
        or selected_wardrobe_connection in partial_wardrobe_connections
    )
    if relevant_wardrobe_partial:
        wardrobe["status"] = "partial"
        wardrobe["snapshot_complete"] = False
        wardrobe["standard_wardrobe_complete"] = False
        wardrobe["full_wardrobe_complete"] = False
        wardrobe["partial_direct_frame"] = True

    lottery_connections = {
        (message.capture_id, message.stream_id)
        for message in messages
        if message.command_id == GP_LUCKYDRAW_OPERATE_RE
    }
    partial_lottery_connections = {
        (capture_id, stream_id)
        for capture_id, stream_id, command_id in partial_targets
        if command_id is None or command_id == GP_LUCKYDRAW_OPERATE_RE
    }
    relevant_lottery_partial = bool(partial_lottery_connections) and (
        not lottery_connections
        or bool(lottery_connections & partial_lottery_connections)
    )
    if relevant_lottery_partial:
        for key in ("draw_count", "gacha_history", "pool_presence"):
            data_coverage[key]["status"] = "partial"
            data_coverage[key]["partial_direct_frame"] = True

    photo_connections = {
        (message.capture_id, message.stream_id)
        for message in messages
        if message.command_id == GP_PHOTO_INFO
    }
    partial_photo_connections = {
        (capture_id, stream_id)
        for capture_id, stream_id, command_id in partial_targets
        if command_id is None or command_id == GP_PHOTO_INFO
    }
    relevant_photo_partial = bool(partial_photo_connections) and (
        not photo_connections or bool(photo_connections & partial_photo_connections)
    )
    if relevant_photo_partial:
        data_coverage["photo_info"]["status"] = "partial"
        data_coverage["photo_info"]["completeness"] = False
        data_coverage["photo_info"]["partial_direct_frame"] = True

    if errors and not streams_summary:
        decode_status = "decode_error"
    elif not streams_summary:
        decode_status = "unobserved"
    elif errors or partial_frames:
        decode_status = "partial"
    else:
        decode_status = "decoded"
    protocol_decode = {
        "status": decode_status,
        "streams": streams_summary,
        "outer_frame_counts": {
            str(type_id): count
            for type_id, count in outer_counts.most_common()
        },
        "candidate_game_message_counts": {
            str(command_id): count
            for command_id, count in candidate_message_counts.most_common()
        },
        "direct_game_message_counts": {
            str(command_id): count
            for command_id, count in direct_message_counts.most_common()
        },
        "client_streams": client_streams_summary,
        "client_outer_frame_counts": {
            str(type_id): count for type_id, count in client_outer_counts.most_common()
        },
        "client_candidate_game_message_counts": {
            str(command_id): count
            for command_id, count in client_candidate_counts.most_common()
        },
        "client_wardrobe_ack_cursors": {
            f"{capture_id}#tcp.stream={stream_id}": cursors
            for (capture_id, stream_id), cursors in sorted(
                wardrobe_ack_cursors.items()
            )
        },
        "partial_frames": partial_frames,
        "semantics": (
            "A partial capture or an unobserved business message is never "
            "interpreted as an absent pool, draw, or wardrobe item. Type-34 "
            "Octets matches are reported as GamedataSend candidates because "
            "the legacy S2C command namespace also contains type 34."
            " Client direction is decoded as plaintext only; Type-34 command "
            "234 is counted separately and is not merged into server coverage. "
            "The corrected GNET compact framing uses 1, 2, 4, or 5 bytes; "
            "Type-18 payload bytes are never treated as a fallback container "
            "when the outer stream is complete. Multiple ring-buffer files "
            "are read in supplied order as one logical capture set so one "
            "connection keeps the same identity across file rollover."
        ),
    }
    return protocol_decode, data_coverage, errors


def _capture_file_entries(
    pcap_files: list[Path], errors: list[str]
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in pcap_files:
        try:
            size = path.stat().st_size
        except OSError as error:
            errors.append(f"{path.name}: unable to stat capture: {error!r}")
            continue
        entries.append({"path": str(path), "bytes": size})
    return entries


def _bundled_pool_catalog_candidates() -> list[Path]:
    module_root = Path(__file__).resolve().parent
    return [
        module_root / "DatAnDict" / "YKAPoolCatalog.json",
        RUNTIME_DIR / "pool_catalog_v3.json",
    ]


def _load_photo_catalog() -> dict[str, Any]:
    candidates = _bundled_pool_catalog_candidates()
    for path in candidates:
        if not path.is_file():
            continue
        data = read_json(path, {})
        if isinstance(data.get("pools"), list):
            return data
    return {}


def _load_lottery_pool_catalog() -> dict[str, Any]:
    candidates = [
        *_bundled_pool_catalog_candidates(),
        RUNTIME_DIR / "lottery_pool_catalog.json",
        RUNTIME_DIR / "pool_id_to_key.json",
        RUNTIME_DIR / "pool_id_to_key_v3.json",
        RUNTIME_DIR / "pool_catalog_v3_20260720" / "pool_id_to_key.json",
    ]
    for path in candidates:
        if not path.is_file():
            continue
        data = read_json(path, {})
        if isinstance(data, dict) and data:
            return data
    return {}


def _locate_catalog_paths(processes: list[dict[str, Any]]) -> list[Path]:
    candidates: list[Path] = []
    for process in processes:
        executable = process.get("exe")
        if not isinstance(executable, str) or not executable:
            continue
        executable_path = Path(executable)
        for parent in (executable_path.parent, *executable_path.parents):
            candidates.extend(
                (
                    parent / "Azure" / "Output" / "package" / "data.png",
                    parent
                    / "Azure"
                    / "StreamingAssets"
                    / "win"
                    / "res_base"
                    / "package"
                    / "data.png",
                )
            )
    seen: set[str] = set()
    existing: list[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve()
        key = str(resolved).casefold()
        if key in seen:
            continue
        seen.add(key)
        if resolved.is_file():
            existing.append(resolved)
    return existing


def _enrich_wardrobe_catalog(
    wardrobe: dict[str, Any],
    processes: list[dict[str, Any]],
    errors: list[str],
) -> None:
    catalog_paths = _locate_catalog_paths(processes)
    if not catalog_paths:
        wardrobe["catalog"] = {
            "status": "unavailable",
            "error": "unable to locate the installed data.png",
        }
        return

    standard_ids = {
        int(fashion["fashion_index"])
        for fashion in wardrobe.get("fashions", [])
        if fashion.get("kind") == "standard"
    }
    loaded_candidates: list[tuple[int, Path, Any]] = []
    rejected_candidates: list[dict[str, str]] = []
    for catalog_path in catalog_paths:
        try:
            candidate_catalog = load_fashion_catalog(catalog_path)
        except CatalogDecodeError as error:
            rejected_candidates.append(
                {"path": str(catalog_path), "error": str(error)}
            )
            continue
        match_count = len(standard_ids & candidate_catalog.entries.keys())
        loaded_candidates.append(
            (match_count, catalog_path, candidate_catalog)
        )

    if not loaded_candidates:
        message = "fashion catalog: no candidate passed strict BCFG validation"
        errors.append(message)
        wardrobe["catalog"] = {
            "status": "decode_error",
            "error": message,
            "candidates": rejected_candidates,
        }
        return

    best_match = max(item[0] for item in loaded_candidates)
    best_candidates = [
        item for item in loaded_candidates if item[0] == best_match
    ]
    best_hashes = {
        item[2].metadata.get("sha256") for item in best_candidates
    }
    if len(best_candidates) > 1 and len(best_hashes) > 1:
        message = (
            "fashion catalog: multiple distinct packages tie for the best "
            "owned-ID match"
        )
        errors.append(message)
        wardrobe["catalog"] = {
            "status": "ambiguous",
            "error": message,
            "candidate_count": len(catalog_paths),
            "candidates": [
                {
                    "path": str(path),
                    "matched_standard_fashion_count": match_count,
                    "sha256": candidate.metadata.get("sha256"),
                }
                for match_count, path, candidate in loaded_candidates
            ],
            "rejected_candidates": rejected_candidates,
        }
        return

    _, catalog_path, catalog = sorted(
        best_candidates, key=lambda item: str(item[1]).casefold()
    )[0]
    if len(catalog_paths) == 1:
        selection_reason = "single_candidate"
    elif len(loaded_candidates) == 1:
        selection_reason = "only_valid_candidate"
    elif len(best_candidates) == 1:
        selection_reason = "best_owned_id_match"
    else:
        selection_reason = "identical_best_candidates"

    matched = 0
    missing: list[int] = []
    part_counts: Counter[str] = Counter()
    quality_counts: Counter[str] = Counter()
    for fashion in wardrobe.get("fashions", []):
        if fashion.get("kind") == "diy_instance":
            fashion.update(
                {
                    "name": None,
                    "part": "DIY定制服装",
                    "quality": None,
                    "suites": [],
                    "catalog_matched": False,
                }
            )
        else:
            fashion_index = int(fashion["fashion_index"])
            static = catalog.entries.get(fashion_index)
            if static is None:
                missing.append(fashion_index)
                fashion["catalog_matched"] = False
                fashion.setdefault("name", None)
                fashion.setdefault("part", "未知")
                fashion.setdefault("quality", None)
                fashion.setdefault("suites", [])
            else:
                matched += 1
                fashion.update(
                    {
                        "name": static["name"]
                        or f"未命名服装 #{fashion_index}",
                        "catalog_name": static["name"],
                        "fashion_type": static["fashion_type"],
                        "part": static["part"],
                        "quality": static["quality"],
                        "is_home_fashion": static["is_home_fashion"],
                        "occasion_type_mask": static["occasion_type_mask"],
                        "suites": static["suites"],
                        "catalog_matched": True,
                    }
                )
        part_counts[str(fashion.get("part") or "未知")] += 1
        quality = fashion.get("quality")
        quality_counts[str(quality) if quality is not None else "unknown"] += 1

    wardrobe["catalog"] = {
        "status": "loaded",
        **catalog.metadata,
        "candidate_count": len(catalog_paths),
        "selection_reason": selection_reason,
        "candidates": [
            {
                "path": str(path),
                "matched_standard_fashion_count": match_count,
                "sha256": candidate.metadata.get("sha256"),
                "fashion_table_version": candidate.metadata.get(
                    "fashion_table_version"
                ),
                "fashion_catalog_count": candidate.metadata.get(
                    "fashion_catalog_count"
                ),
            }
            for match_count, path, candidate in sorted(
                loaded_candidates, key=lambda item: str(item[1]).casefold()
            )
        ],
        "rejected_candidates": rejected_candidates,
        "matched_standard_fashion_count": matched,
        "missing_standard_fashion_count": len(missing),
        "missing_standard_fashion_ids": missing[:100],
    }
    wardrobe["part_counts"] = dict(sorted(part_counts.items()))
    wardrobe["quality_counts"] = dict(sorted(quality_counts.items()))


def _persist_report(
    session_dir: Path,
    report: dict[str, Any],
    state: str,
) -> dict[str, Any]:
    document = dict(report)
    report_path = session_dir / REPORT_FILENAME
    document["persistence"] = {
        "state": state,
        "written_at": now_iso(),
        "path": str(report_path),
    }
    atomic_write_json(report_path, document)
    return document


def _validated_session_dir(
    session_dir: Path,
    sessions_root: Path | None = None,
) -> Path:
    candidate = Path(session_dir).resolve()
    root = Path(sessions_root or SESSIONS_DIR).resolve()
    if candidate == root or root not in candidate.parents:
        raise ValueError("会话目录不在允许的 sessions 目录内")
    return candidate


def _is_link_or_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    try:
        attributes = int(getattr(path.lstat(), "st_file_attributes", 0))
    except OSError:
        return False
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_flag)


def persist_wechat_export(
    session_dir: Path,
    payload: dict[str, Any],
    *,
    sessions_root: Path | None = None,
) -> Path:
    candidate = _validated_session_dir(session_dir, sessions_root)
    if not isinstance(payload, dict):
        raise TypeError("微信导出数据必须是对象")
    target = candidate / WECHAT_EXPORT_FILENAME
    atomic_write_json(target, payload)
    return target


def cleanup_session_capture_files(
    session_dir: Path,
    *,
    sessions_root: Path | None = None,
) -> dict[str, Any]:
    candidate = _validated_session_dir(session_dir, sessions_root)
    status = read_json(candidate / "status.json", {})
    if not isinstance(status, dict) or status.get("state") != "stopped":
        raise RuntimeError("采集器尚未停止，拒绝清理抓包文件")

    report = read_json(candidate / REPORT_FILENAME, {})
    persistence = report.get("persistence", {}) if isinstance(report, dict) else {}
    if not isinstance(persistence, dict) or persistence.get("state") != "final":
        raise RuntimeError("最终报告尚未落盘，拒绝清理抓包文件")

    export = read_json(candidate / WECHAT_EXPORT_FILENAME, {})
    if not isinstance(export, dict) or not export:
        raise RuntimeError("微信导出数据尚未落盘，拒绝清理抓包文件")
    if export.get("report_generated_at") != report.get("generated_at"):
        raise RuntimeError("微信导出数据与最终报告不匹配，拒绝清理抓包文件")

    pcap_dir = candidate / "pcap"
    removed_files: list[str] = []
    removed_bytes = 0
    if _is_link_or_reparse_point(pcap_dir):
        raise RuntimeError("抓包目录不能是链接或重解析点，拒绝清理")
    paths = sorted(
        {
            *pcap_dir.glob("*.pcapng"),
            *pcap_dir.glob("*.pcap"),
        }
    ) if pcap_dir.is_dir() else []
    expected_parent = pcap_dir.resolve()
    if expected_parent.parent != candidate:
        raise RuntimeError("抓包目录路径越界，拒绝清理")
    for path in paths:
        if (
            _is_link_or_reparse_point(pcap_dir)
            or pcap_dir.resolve() != expected_parent
        ):
            raise RuntimeError("抓包目录在清理期间发生变化，拒绝继续")
        if _is_link_or_reparse_point(path):
            raise RuntimeError("抓包文件不能是链接或重解析点，拒绝清理")
        resolved = path.resolve()
        if resolved.parent != expected_parent:
            raise RuntimeError("抓包文件路径越界，拒绝清理")
        try:
            size = resolved.stat().st_size
        except OSError:
            size = 0
        for attempt in range(20):
            try:
                path.unlink(missing_ok=True)
                break
            except OSError as error:
                retryable = isinstance(error, PermissionError) or getattr(
                    error, "winerror", None
                ) in {5, 32}
                if not retryable or attempt == 19:
                    raise
                time.sleep(0.05 * (attempt + 1))
        removed_files.append(resolved.name)
        removed_bytes += size

    result = {
        "schema_version": 1,
        "cleaned_at": now_iso(),
        "session_dir": str(candidate),
        "removed_file_count": len(removed_files),
        "removed_bytes": removed_bytes,
        "removed_files": removed_files,
        "report_generated_at": report.get("generated_at"),
    }
    atomic_write_json(candidate / CAPTURE_CLEANUP_FILENAME, result)
    return result


def build_session_report(session_dir: Path) -> dict[str, Any]:
    session_dir = session_dir.resolve()
    with _REPORT_BUILD_LOCK:
        events, event_parse_errors = _read_events(session_dir / "events.jsonl")
        pcap_files = sorted((session_dir / "pcap").glob("*.pcapng"))
        processes = [
            event for event in events if event.get("type") == "target_process"
        ]
        flows = [event for event in events if event.get("type") == "network_flow"]
        open_files = [event for event in events if event.get("type") == "open_file"]
        protocols, capture_errors = _protocol_counts(pcap_files)
        protocol_decode, data_coverage, decode_errors = _decode_game_traffic(pcap_files)
        capture_errors.extend(decode_errors)
        report = {
            "schema_version": 3,
            "generated_at": now_iso(),
            "session": read_json(session_dir / "session.json", {}),
            "status": read_json(session_dir / "status.json", {}),
            "target_processes": processes,
            "network_flows": flows,
            "open_files": open_files,
            "capture_files": _capture_file_entries(pcap_files, capture_errors),
            "protocol_counts": dict(protocols.most_common()),
            "protocol_decode": protocol_decode,
            "event_parse_errors": event_parse_errors,
            "capture_parse_errors": capture_errors,
            "data_coverage": data_coverage,
        }
        _enrich_wardrobe_catalog(
            data_coverage["wardrobe_presence"], processes, capture_errors
        )
        return _persist_report(session_dir, report, "final")


def build_live_coverage(session_dir: Path) -> dict[str, Any]:
    """Decode the current capture and atomically persist the live report."""
    session_dir = session_dir.resolve()
    with _REPORT_BUILD_LOCK:
        existing = read_json(session_dir / REPORT_FILENAME, {})
        if isinstance(existing, dict):
            persistence = existing.get("persistence", {})
            if isinstance(persistence, dict) and persistence.get("state") == "final":
                return existing
        pcap_files = sorted((session_dir / "pcap").glob("*.pcapng"))
        protocol_decode, data_coverage, decode_errors = _decode_game_traffic(pcap_files)
        report = {
            "schema_version": 3,
            "generated_at": now_iso(),
            "session_dir": str(session_dir),
            "protocol_decode": protocol_decode,
            "data_coverage": data_coverage,
            "capture_parse_errors": decode_errors,
        }
        return _persist_report(session_dir, report, "live")


def analyze_session(session_dir: Path) -> dict[str, Any]:
    """Compatibility alias for the persistent final report builder."""
    return build_session_report(session_dir)
