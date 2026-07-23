from __future__ import annotations

import json
from pathlib import Path

import pytest

from YKABusiness import _analyze_photo_info, _analyze_photo_operate
from YKAProtocol import GameMessage
from YKAWechatImport import (
    ImportDataError,
    _photo_snapshot_ids,
    generate_import_code_from_report,
)


CATALOG_SHA = "A" * 64
DRAW_SOURCE_FIELD = (
    "gp_luckydraw_operate_re.pool_info.amount (protobuf field 5)"
)


def _pool(key: str, lottery_pool_id: object = None) -> dict[str, object]:
    pool: dict[str, object] = {
        "key": key,
        "name": key,
        "att_type": "attlx",
        "piece_count": 1,
        "configured_piece_count": 1,
        "notz": False,
        "main_fashion_ids": [101],
        "main_requirement": "any",
        "mapping_confidence": "verified",
        "piece_fashion_ids": [101],
        "piece_mapping_confidence": "verified_complete",
        "piece_marks": [
            {
                "slot_index": 0,
                "fashion_ids": [101],
                "fashion_name": "测试服装",
                "part": "连衣裙",
            }
        ],
        "image_geometry": {
            "source_width": 1000,
            "source_height": 500,
            "source": "cached_pool_image",
            "slot_centers": [[0.5, 0.5]],
        },
        "suite_id": 1,
        "suite_name": key,
        "suite_fashion_ids": [101],
        "suite_piece_count": 1,
        "suite_mapping_confidence": "verified",
        "status_fashions": [
            {
                "fashion_id": 101,
                "color_plate_count": 16,
                "fashion_evolution_item_id": 1,
            }
        ],
    }
    if lottery_pool_id is not None:
        pool["lottery_pool_id"] = lottery_pool_id
    return pool


def _draw_evidence(
    by_pool_id: dict[str, object],
    by_pool_key: dict[str, object],
    *,
    evidence_level: str = "direct",
) -> dict[str, object]:
    return {
        "evidence_level": evidence_level,
        "evidence_sources": (
            ["gamedata_candidate"]
            if evidence_level == "candidate"
            else ["direct", "gamedata_candidate"]
            if evidence_level == "mixed"
            else ["direct"]
        ),
        "status": "observed_present",
        "value": None,
        "by_pool_id": by_pool_id,
        "by_pool_key": by_pool_key,
        "unmapped_by_pool_id": {},
        "observed_pool_count": len(by_pool_id),
        "snapshot_complete": True,
        "captured_draw_count": None,
        "scope": "server_pool_snapshot",
        "evidence_messages": 1,
        "source_field": DRAW_SOURCE_FIELD,
        "pool_id_to_key_catalog": {
            "status": "loaded",
            "mapped_pool_count": len(by_pool_key),
            "unmapped_pool_count": 0,
        },
        "duplicate_pool_ids": [],
        "completeness": True,
    }


def _encode_varint(value: int) -> bytes:
    v = value & 0xFFFFFFFF if value < 0 else value
    encoded = bytearray()
    while True:
        byte = v & 0x7F
        v >>= 7
        if v:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            break
    return bytes(encoded)


def _command740_payload(
    *,
    op_type: int = 1,
    errcode: int = 0,
    unpacked_field6: list[int] | None = None,
    packed_field6: list[int] | None = None,
) -> bytes:
    pieces: list[bytes] = [
        b"\x10" + _encode_varint(op_type),
        b"\x18" + _encode_varint(errcode),
    ]
    for value in unpacked_field6 or []:
        pieces.append(b"\x30" + _encode_varint(value))
    if packed_field6:
        packed = b"".join(_encode_varint(value) for value in packed_field6)
        pieces.append(b"\x32" + _encode_varint(len(packed)) + packed)
    return b"".join(pieces)


def _analyze_command740(payload: bytes) -> dict[str, object]:
    return _analyze_photo_operate(
        [
            GameMessage(
                command_id=740,
                payload=payload,
                frame_offset=0,
                source="direct",
            )
        ]
    )


def _background_pool(
    key: str,
    shot_src_ids: list[int],
    *,
    scene_ids: list[int] | None = None,
    unavailable: bool = False,
) -> dict[str, object]:
    # scene_ids identify catalog scenes; command 740 reports those scenes'
    # lock_id values directly through shot_src_ids.
    pool: dict[str, object] = {
        "key": key,
        "att_type": "background",
        "mapping_confidence": "verified",
        "scene_ids": [999999] if scene_ids is None else scene_ids,
        "shot_src_ids": shot_src_ids,
        "mapping_evidence": {"source_lock_ids": shot_src_ids},
    }
    if unavailable:
        pool["unavailable_in_installed_version"] = True
        pool["scene_ids"] = []
        pool["shot_src_ids"] = []
    return pool


def _write_catalog(
    path: Path, pools: list[dict[str, object]], schema_version: int = 5
) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": schema_version,
                "game_catalog": {
                    "sha256": CATALOG_SHA,
                    "fashion_catalog_count": 9389,
                },
                "pools": pools,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def _report_object(draw_count: dict[str, object]) -> dict[str, object]:
    return {
                "generated_at": "2026-07-20T00:00:00+08:00",
                "data_coverage": {
                    "wardrobe_presence": {
                        "snapshot_complete": True,
                        "standard_wardrobe_complete": True,
                        "standard_fashion_count": 1,
                        "fashions": [
                            {
                                "kind": "standard",
                                "fashion_index": 101,
                                "owned": True,
                                "ui_owned": True,
                            }
                        ],
                        "catalog": {
                            "status": "loaded",
                            "sha256": CATALOG_SHA,
                            "fashion_catalog_count": 9389,
                        },
                    },
                    "draw_count": draw_count,
                },
            }


def _generate(
    tmp_path: Path,
    pools: list[dict[str, object]],
    draw_count: dict[str, object],
):
    catalog = tmp_path / "catalog.json"
    _write_catalog(catalog, pools)
    return generate_import_code_from_report(_report_object(draw_count), catalog)


def _generate_with_shot_src_unlocks(
    tmp_path: Path,
    pools: list[dict[str, object]],
    shot_src_unlocks: dict[str, object],
    *,
    schema_version: int = 5,
    photo_ids: list[int] | None = None,
    photo_info: dict[str, object] | None = None,
):
    catalog = tmp_path / "catalog.json"
    _write_catalog(catalog, pools, schema_version=schema_version)
    report = _report_object(_draw_evidence({}, {}))
    report["data_coverage"]["shot_src_unlocks"] = shot_src_unlocks
    report["data_coverage"]["photo_info"] = (
        _complete_photo_snapshot(photo_ids or [])
        if photo_info is None
        else photo_info
    )
    return generate_import_code_from_report(report, catalog)


def _complete_photo_snapshot(photo_ids: list[int]) -> dict[str, object]:
    return {
        "status": "observed_present",
        "completeness": True,
        "partial_flag": 0,
        "records": [
            {
                "complete": True,
                "partial_flag": 0,
                "photo_ids": photo_ids,
            }
        ],
    }


def _rows_by_key(code: str) -> dict[str, list[object]]:
    rows = json.loads(code)
    return {row[0]: row for row in rows}


def test_photo_snapshot_requires_explicit_zero_partial_flags() -> None:
    photo_info = {
        "status": "observed_present",
        "completeness": True,
        "partial_flag": 0,
        "records": [
            {
                "complete": True,
                "partial_flag": 0,
                "photo_ids": [123],
            }
        ],
    }

    assert _photo_snapshot_ids(photo_info) == ({123}, True)

    missing_top_flag = dict(photo_info)
    missing_top_flag.pop("partial_flag")
    assert _photo_snapshot_ids(missing_top_flag) == (set(), False)

    float_top_flag = dict(photo_info)
    float_top_flag["partial_flag"] = 0.0
    assert _photo_snapshot_ids(float_top_flag) == (set(), False)

    null_record_flag = dict(photo_info)
    null_record_flag["records"] = [dict(photo_info["records"][0])]
    null_record_flag["records"][0]["partial_flag"] = None
    assert _photo_snapshot_ids(null_record_flag) == (set(), False)

    float_record_flag = dict(photo_info)
    float_record_flag["records"] = [dict(photo_info["records"][0])]
    float_record_flag["records"][0]["partial_flag"] = -0.0
    assert _photo_snapshot_ids(float_record_flag) == (set(), False)


def test_photo_analysis_normalizes_missing_field4_to_complete_zero() -> None:
    photo_info = _analyze_photo_info(
        [
            GameMessage(
                command_id=637,
                payload=b"\x12\x02\x08\x7b",
                frame_offset=0,
                source="direct",
            )
        ]
    )

    assert photo_info["status"] == "observed_present"
    assert photo_info["completeness"] is True
    assert photo_info["partial_flag"] == 0
    assert photo_info["records"][0]["complete"] is True
    assert photo_info["records"][0]["partial_flag"] == 0


def test_complete_737_snapshot_writes_nonzero_ordinary_draw_count(
    tmp_path: Path,
) -> None:
    result = _generate(
        tmp_path,
        [_pool("p1", 7)],
        _draw_evidence({"7": 23}, {"p1": 23}),
    )

    assert _rows_by_key(result.code)["p1"][1] == 23
    assert result.observed_draw_pool_count == 1
    assert result.unobserved_draw_count == 0


def test_in_memory_report_writes_nonzero_draw_count_without_report_file(
    tmp_path: Path,
) -> None:
    catalog = tmp_path / "catalog.json"
    _write_catalog(catalog, [_pool("p1", 7)])
    result = generate_import_code_from_report(
        _report_object(_draw_evidence({"7": 23}, {"p1": 23})),
        catalog,
    )

    assert _rows_by_key(result.code)["p1"][1] == 23
    assert result.observed_draw_pool_count == 1


@pytest.mark.parametrize(
    "report_catalog",
    [
        None,
        {"status": "decode_error", "error": "new package format"},
        {"status": "unavailable"},
    ],
)
def test_complete_wardrobe_uses_frozen_catalog_when_local_catalog_is_unusable(
    tmp_path: Path,
    report_catalog: object,
) -> None:
    catalog = tmp_path / "catalog.json"
    _write_catalog(catalog, [_pool("p1", 7)])
    report = _report_object(_draw_evidence({"7": 23}, {"p1": 23}))
    report["data_coverage"]["wardrobe_presence"]["catalog"] = report_catalog

    result = generate_import_code_from_report(report, catalog)

    assert _rows_by_key(result.code)["p1"][1] == 23
    assert any("冻结小程序目录" in warning for warning in result.warnings)


def test_frozen_catalog_fallback_still_rejects_incomplete_wardrobe(
    tmp_path: Path,
) -> None:
    catalog = tmp_path / "catalog.json"
    _write_catalog(catalog, [_pool("p1", 7)])
    report = _report_object(_draw_evidence({"7": 23}, {"p1": 23}))
    wardrobe = report["data_coverage"]["wardrobe_presence"]
    wardrobe["catalog"] = {"status": "decode_error"}
    wardrobe["snapshot_complete"] = False

    with pytest.raises(ImportDataError, match="衣柜快照不完整"):
        generate_import_code_from_report(report, catalog)


def test_loaded_but_malformed_report_catalog_does_not_use_fallback(
    tmp_path: Path,
) -> None:
    catalog = tmp_path / "catalog.json"
    _write_catalog(catalog, [_pool("p1", 7)])
    report = _report_object(_draw_evidence({"7": 23}, {"p1": 23}))
    report["data_coverage"]["wardrobe_presence"]["catalog"] = {
        "status": "loaded"
    }

    with pytest.raises(ImportDataError, match="静态服装目录版本无效"):
        generate_import_code_from_report(report, catalog)


def test_ambiguous_report_catalog_does_not_use_fallback(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    _write_catalog(catalog, [_pool("p1", 7)])
    report = _report_object(_draw_evidence({"7": 23}, {"p1": 23}))
    report["data_coverage"]["wardrobe_presence"]["catalog"] = {
        "status": "ambiguous"
    }

    with pytest.raises(ImportDataError, match="没有可核验的静态服装目录"):
        generate_import_code_from_report(report, catalog)


def test_shared_lottery_pool_id_writes_same_value_to_both_aliases(
    tmp_path: Path,
) -> None:
    result = _generate(
        tmp_path,
        [_pool("wxz29", 81), _pool("wxf29", 81)],
        _draw_evidence(
            {"81": 20},
            {"wxz29": 20, "wxf29": 20},
        ),
    )

    rows = _rows_by_key(result.code)
    assert rows["wxz29"][1] == 20
    assert rows["wxf29"][1] == 20
    assert sum(row[1] for row in rows.values()) == 40
    assert result.observed_draw_pool_count == 2
    assert result.unobserved_draw_count == 0


def test_report_key_mapping_mismatch_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ImportDataError):
        _generate(
            tmp_path,
            [_pool("p1", 7)],
            _draw_evidence({"7": 23}, {"p1": 24}),
        )


@pytest.mark.parametrize("invalid_count", [-1, True])
def test_negative_or_boolean_draw_count_is_rejected(
    tmp_path: Path,
    invalid_count: object,
) -> None:
    with pytest.raises(ImportDataError):
        _generate(
            tmp_path,
            [_pool("p1", 7)],
            _draw_evidence(
                {"7": invalid_count},
                {"p1": invalid_count},
            ),
        )


@pytest.mark.parametrize("invalid_pool_id", [0, -1, True])
def test_catalog_lottery_pool_id_must_be_a_positive_non_boolean_integer(
    tmp_path: Path,
    invalid_pool_id: object,
) -> None:
    with pytest.raises(ImportDataError):
        _generate(
            tmp_path,
            [_pool("p1", invalid_pool_id)],
            _draw_evidence({"7": 23}, {"p1": 23}),
        )


def test_unobserved_catalog_pools_remain_zero_and_are_counted(
    tmp_path: Path,
) -> None:
    result = _generate(
        tmp_path,
        [
            _pool("observed", 7),
            _pool("missing-from-snapshot", 8),
            _pool("no-server-mapping"),
        ],
        _draw_evidence({"7": 23}, {"observed": 23}),
    )

    rows = _rows_by_key(result.code)
    assert rows["observed"][1] == 23
    assert rows["missing-from-snapshot"][1] == 0
    assert rows["no-server-mapping"][1] == 0
    assert result.observed_draw_pool_count == 1
    assert result.unobserved_draw_count == 2


def test_candidate_draw_evidence_is_written_and_labeled_with_warning(
    tmp_path: Path,
) -> None:
    result = _generate(
        tmp_path,
        [_pool("p1", 7)],
        _draw_evidence(
            {"7": 9},
            {"p1": 9},
            evidence_level="candidate",
        ),
    )

    assert _rows_by_key(result.code)["p1"][1] == 9
    assert result.draw_evidence_level == "candidate"
    assert any("候选" in warning for warning in result.warnings)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "partial"),
        ("snapshot_complete", False),
        ("completeness", False),
    ],
)
def test_partial_or_incomplete_draw_evidence_is_never_imported(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    draw_count = _draw_evidence({"7": 23}, {"p1": 23})
    draw_count[field] = value

    result = _generate(tmp_path, [_pool("p1", 7)], draw_count)

    assert _rows_by_key(result.code)["p1"][1] == 0
    assert result.observed_draw_pool_count == 0
    assert result.unobserved_draw_count == 1


@pytest.mark.parametrize(("op_type", "errcode"), [(2, 0), (1, 1)])
def test_command740_op_type_and_field3_errcode_required_for_snapshot(
    tmp_path: Path,
    op_type: int,
    errcode: int,
) -> None:
    snapshot = _analyze_command740(
        _command740_payload(op_type=op_type, errcode=errcode)
    )
    assert snapshot["records"][0]["op_type"] == op_type
    assert snapshot["records"][0]["errcode"] == errcode
    assert snapshot["snapshot_complete"] is False
    assert snapshot["status"] == "partial"


def test_command740_rejects_duplicate_singular_fields() -> None:
    payload = _command740_payload() + b"\x10\x01" + b"\x18\x00"
    snapshot = _analyze_command740(payload)
    assert snapshot["snapshot_complete"] is False
    assert snapshot["status"] == "partial"


def test_command740_rejects_non_varint_singular_fields() -> None:
    snapshot = _analyze_command740(b"\x12\x01x" + _command740_payload(errcode=0)[2:])
    assert snapshot["snapshot_complete"] is False


@pytest.mark.parametrize(("field", "value"), [("op_type", True), ("errcode", 0.0)])
def test_shot_evidence_rejects_non_integer_numeric_fields(
    tmp_path: Path, field: str, value: object
) -> None:
    snapshot = _analyze_command740(_command740_payload())
    snapshot["records"][0][field] = value
    with pytest.raises(ImportDataError):
        _generate_with_shot_src_unlocks(tmp_path, [_background_pool("bg", [111])], snapshot)


def test_command740_accepts_unpacked_and_packed_field6_and_count0_means_no_ownership(
    tmp_path: Path,
) -> None:
    snapshot = _analyze_command740(
        _command740_payload(
            unpacked_field6=[111, 0, 10],
            packed_field6=[222, 3, 20],
        )
    )

    assert snapshot["status"] == "observed_present"
    assert snapshot["snapshot_complete"] is True
    assert snapshot["record_count"] == 2
    assert snapshot["field6_value_count"] == 6
    assert snapshot["owned_tmp_ids"] == [222]

    result = _generate_with_shot_src_unlocks(
        tmp_path,
        [_background_pool("bg", [111])],
        snapshot,
    )
    assert _rows_by_key(result.code)["bg"][1] == 0


def test_command637_portrait_id_collision_does_not_mark_background_owned(
    tmp_path: Path,
) -> None:
    snapshot = _analyze_command740(_command740_payload(unpacked_field6=[999, 0, 10]))
    result = _generate_with_shot_src_unlocks(
        tmp_path,
        [_background_pool("bg", [111], scene_ids=[123])],
        snapshot,
        photo_ids=[123],
    )

    assert _rows_by_key(result.code)["bg"][1] == 0


def test_complete_command740_proves_zero_even_if_command637_is_incomplete(
    tmp_path: Path,
) -> None:
    shot_snapshot = _analyze_command740(
        _command740_payload(unpacked_field6=[222, 0, 10])
    )
    incomplete_photo = _complete_photo_snapshot([])
    incomplete_photo["completeness"] = False

    result = _generate_with_shot_src_unlocks(
        tmp_path,
        [_background_pool("bg", [111], scene_ids=[123])],
        shot_snapshot,
        photo_info=incomplete_photo,
    )

    assert _rows_by_key(result.code)["bg"][1] == 0


def test_unavailable_background_remains_zero_without_snapshots(
    tmp_path: Path,
) -> None:
    incomplete_shot = {"status": "partial"}
    result = _generate_with_shot_src_unlocks(
        tmp_path,
        [_background_pool("bg", [111], unavailable=True)],
        incomplete_shot,
        photo_info={"status": "partial"},
    )

    assert _rows_by_key(result.code)["bg"][1] == 0


@pytest.mark.parametrize(
    "field6_values",
    [
        [111, 1],  # 非3倍数
        [111, -1, 10],  # 负值
    ],
)
def test_command740_rejects_invalid_field6(
    tmp_path: Path,
    field6_values: list[int],
) -> None:
    snapshot = _analyze_command740(
        _command740_payload(unpacked_field6=field6_values)
    )

    assert snapshot["status"] == "partial"
    assert snapshot["snapshot_complete"] is False


def test_command740_rejects_duplicate_tmp_id_in_field6(
    tmp_path: Path,
) -> None:
    snapshot = _analyze_command740(
        _command740_payload(
            unpacked_field6=[111, 1, 10, 111, 2, 20],
        )
    )

    assert snapshot["status"] == "partial"
    assert snapshot["snapshot_complete"] is False
    assert snapshot["duplicate_tmp_ids"] == [111]


def test_command740_rejects_non_740_shot_src_import(
    tmp_path: Path,
) -> None:
    shot_src_only_637: dict[str, object] = {
        "status": "observed_present",
        "snapshot_complete": True,
        "source_command": 637,
        "op_type": 1,
        "duplicate_tmp_ids": [],
        "parse_errors": [],
        "complete_frames": 1,
        "observed_frames": 1,
        "record_count": 0,
        "field6_value_count": 0,
        "records": [{"complete": True, "triples": []}],
    }

    with pytest.raises(ImportDataError, match="命令740快照不完整"):
        _generate_with_shot_src_unlocks(
            tmp_path,
            [_background_pool("bg", [111])],
            shot_src_only_637,
        )


def test_malformed_command740_cannot_fall_back_to_external_ownership(
    tmp_path: Path,
) -> None:
    catalog = tmp_path / "catalog.json"
    _write_catalog(catalog, [_background_pool("bg", [111])])
    report = _report_object(_draw_evidence({}, {}))
    report["data_coverage"]["shot_src_unlocks"] = {"status": "partial"}

    with pytest.raises(ImportDataError, match="外部背景所有权映射已禁用"):
        generate_import_code_from_report(
            report,
            catalog,
            background_ownership={"bg": True},
        )


def test_complete_command740_snapshot_matches_any_shot_src_id(
    tmp_path: Path,
) -> None:
    snapshot = _analyze_command740(
        _command740_payload(
            unpacked_field6=[111, 0, 10, 222, 1, 20],
        )
    )
    result = _generate_with_shot_src_unlocks(
        tmp_path,
        [_background_pool("bg", [222, 333])],
        snapshot,
    )

    assert _rows_by_key(result.code)["bg"][1] == 1


def test_schema4_background_mapping_is_not_reused_as_schema5_lock_id(
    tmp_path: Path,
) -> None:
    snapshot = _analyze_command740(
        _command740_payload(
            unpacked_field6=[333, 1, 20],
        )
    )
    with pytest.raises(ImportDataError, match="映射或所有权未知"):
        _generate_with_shot_src_unlocks(
            tmp_path,
            [_background_pool("bg", [333])],
            snapshot,
            schema_version=4,
        )


def test_schema5_rejects_unlock_way_target_as_source_lock_evidence(tmp_path: Path) -> None:
    pool = _background_pool("bg", [25571])
    pool["mapping_evidence"] = {"source_lock_ids": [16234]}
    snapshot = _analyze_command740(
        _command740_payload(unpacked_field6=[16234, 1, 20])
    )

    with pytest.raises(ImportDataError, match="不是场景 lock_id"):
        _generate_with_shot_src_unlocks(tmp_path, [pool], snapshot)


def test_old_unlock_way_target_collision_does_not_mark_background_owned(
    tmp_path: Path,
) -> None:
    snapshot = _analyze_command740(
        _command740_payload(unpacked_field6=[16234, 1, 20])
    )
    result = _generate_with_shot_src_unlocks(
        tmp_path,
        [_background_pool("bg", [25571])],
        snapshot,
    )

    assert _rows_by_key(result.code)["bg"][1] == 0
