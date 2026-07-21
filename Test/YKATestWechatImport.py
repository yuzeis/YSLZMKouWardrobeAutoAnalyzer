from __future__ import annotations

import json
from pathlib import Path

import pytest

from YKAWechatImport import (
    ImportDataError,
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


def _write_catalog(path: Path, pools: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 3,
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


def _rows_by_key(code: str) -> dict[str, list[object]]:
    rows = json.loads(code)
    return {row[0]: row for row in rows}


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
