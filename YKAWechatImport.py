from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


STATUS_TO_CODE = {
    "未抽齐": 0,
    "有裙": 1,
    "全齐": 2,
    "扩裙": 3,
    "全扩": 4,
    "特姿": 5,
    "特姿裙幻": 6,
    "千幻": 7,
    "想抽": 8,
    "全齐裙幻": 9,
    "全扩裙幻": 10,
}

VALID_STATUS_CODES = frozenset(STATUS_TO_CODE.values())
VERIFIED_MAPPING_LEVELS = frozenset({"verified", "high", "manual_confirmed"})
MAX_SAFE_INTEGER = 9_007_199_254_740_991
COORDINATE_SCALE = 1_000_000
DRAW_SOURCE_FIELD = (
    "gp_luckydraw_operate_re.pool_info.amount (protobuf field 5)"
)
SUPPORTED_DRAW_EVIDENCE_LEVELS = frozenset({"candidate", "direct", "mixed"})


class ImportDataError(ValueError):
    pass


@dataclass(frozen=True)
class WardrobeEvidence:
    generated_at: str
    owned_fashion_ids: frozenset[int]
    fashion_records: dict[int, dict[str, int | None]]
    standard_fashion_count: int
    catalog_sha256: str
    catalog_fashion_count: int


@dataclass(frozen=True)
class ImportRecord:
    pool_key: str
    draw_count: int
    status_code: int
    mark_points: tuple[tuple[int, int], ...] = ()
    background: bool = False

    def to_row(self) -> list[Any]:
        if self.background:
            return [self.pool_key, self.draw_count]
        row: list[Any] = [self.pool_key, self.draw_count, self.status_code]
        if self.mark_points:
            flattened = [value for point in self.mark_points for value in point]
            # The fifth element is markPoints. The mini program requires the
            # empty fourth remark element when markPoints are present.
            row.extend(["", flattened])
        return row


@dataclass(frozen=True)
class ImportResult:
    code: str
    records: tuple[ImportRecord, ...]
    catalog_pool_count: int
    complete_piece_pool_count: int
    unresolved_piece_pool_count: int
    mapped_piece_count: int
    marked_owned_piece_count: int
    owned_main_count: int
    full_set_count: int
    missing_main_count: int
    unresolved_status_pool_count: int
    target_image_width_px: int
    warnings: tuple[str, ...]
    unobserved_draw_count: int = 0
    observed_draw_pool_count: int = 0
    background_pool_count: int = 0
    observed_draw_source_pool_count: int = 0
    unmapped_server_draw_pool_count: int = 0
    draw_evidence_level: str = "none"


@dataclass(frozen=True)
class DrawCountImport:
    by_pool_key: dict[str, int]
    observed_source_pool_count: int
    unmapped_source_pool_count: int
    evidence_level: str
    snapshot_usable: bool
    status: str


def _ensure_int_or_none(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ImportDataError(f"无法读取文件：{path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ImportDataError(f"JSON 格式错误：{path}: {error}") from error
    if not isinstance(value, dict):
        raise ImportDataError(f"JSON 根节点必须是对象：{path}")
    return value


def _photo_snapshot_ids(photo_info: Any) -> tuple[set[int], bool]:
    """Extract command-637 field2/photo ids without guessing partial snapshots."""
    if not isinstance(photo_info, dict):
        return set(), False
    if (
        photo_info.get("status") != "observed_present"
        or photo_info.get("completeness") is not True
        or photo_info.get("partial_flag", 0) not in (0, False)
    ):
        return set(), False
    records = photo_info.get("records")
    if not isinstance(records, list):
        return set(), False

    ids: set[int] = set()
    for record in records:
        if not isinstance(record, dict):
            return set(), False
        if (
            record.get("complete") is not True
            or record.get("partial_flag", 0) not in (0, False)
        ):
            return set(), False
        values = record.get("photo_ids")
        if not isinstance(values, list):
            values = record.get("field2_photo_info")
        if not isinstance(values, list):
            return set(), False
        for value in values:
            if isinstance(value, int) and not isinstance(value, bool):
                photo_id = value
            elif isinstance(value, dict):
                photo_id = value.get("id", value.get("photo_id"))
            else:
                return set(), False
            if not isinstance(photo_id, int) or isinstance(photo_id, bool) or photo_id <= 0:
                return set(), False
            ids.add(photo_id)
    return ids, True


def _positive_int_list(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, int) and not isinstance(item, bool) and item > 0
        for item in value
    )


def _pool_kind(pool: dict[str, Any]) -> str:
    return str(
        pool.get(
            "pool_type",
            pool.get(
                "type",
                pool.get("kind", pool.get("att_type", pool.get("attType", ""))),
            ),
        )
    ).lower()


def _is_background_pool(pool: dict[str, Any]) -> bool:
    return _pool_kind(pool) in {"background", "bg", "attbg"}


def load_pool_catalog(path: Path) -> dict[str, Any]:
    catalog = _load_json_object(path)
    if catalog.get("schema_version") not in {2, 3}:
        raise ImportDataError("不支持的卡池目录版本")
    raw_pools = catalog.get("pools")
    if not isinstance(raw_pools, list) or not raw_pools:
        raise ImportDataError("卡池目录没有 pools 数据")
    pools = list(raw_pools)
    background_entries = catalog.get("backgrounds", catalog.get("background_pools", []))
    if background_entries not in (None, []):
        if not isinstance(background_entries, list):
            raise ImportDataError("卡池目录的 backgrounds 数据无效")
        pools.extend(background_entries)

    game_catalog = catalog.get("game_catalog")
    if not isinstance(game_catalog, dict) or not isinstance(
        game_catalog.get("sha256"), str
    ):
        raise ImportDataError("卡池目录缺少游戏服装目录版本")

    seen: set[str] = set()
    for position, pool in enumerate(pools):
        if not isinstance(pool, dict):
            raise ImportDataError(f"卡池目录第 {position + 1} 项不是对象")
        key = pool.get("key")
        if not isinstance(key, str) or not key:
            raise ImportDataError(f"卡池目录第 {position + 1} 项缺少 key")
        if key in seen:
            raise ImportDataError(f"卡池 key 重复：{key}")
        seen.add(key)

        if _is_background_pool(pool):
            scene_ids = pool.get("scene_ids")
            if (
                not isinstance(scene_ids, list)
                or any(
                    not isinstance(scene_id, int)
                    or isinstance(scene_id, bool)
                    or scene_id <= 0
                    for scene_id in scene_ids
                )
                or len(scene_ids) != len(set(scene_ids))
            ):
                raise ImportDataError(f"背景 {key} 的 scene_ids 无效")
            unavailable = pool.get("unavailable_in_installed_version") is True
            if unavailable:
                if scene_ids:
                    raise ImportDataError(f"版本缺失背景 {key} 不应包含 scene_ids")
            elif pool.get("mapping_confidence") not in VERIFIED_MAPPING_LEVELS or not scene_ids:
                raise ImportDataError(f"背景 {key} 缺少已核验的场景映射")
            continue

        lottery_pool_id = pool.get("lottery_pool_id")
        if lottery_pool_id is not None and (
            not isinstance(lottery_pool_id, int)
            or isinstance(lottery_pool_id, bool)
            or lottery_pool_id <= 0
            or lottery_pool_id > MAX_SAFE_INTEGER
        ):
            raise ImportDataError(f"卡池 {key} 的 lottery_pool_id 无效")

        if not _positive_int_list(pool.get("main_fashion_ids", [])):
            raise ImportDataError(f"卡池 {key} 的 main_fashion_ids 无效")
        if pool.get("main_requirement", "any") not in {"any", "all"}:
            raise ImportDataError(f"卡池 {key} 的 main_requirement 无效")

        status_fashions = pool.get("status_fashions")
        if not isinstance(status_fashions, list):
            raise ImportDataError(f"卡池 {key} 的 status_fashions 无效")
        status_ids: set[int] = set()
        for status_fashion in status_fashions:
            if not isinstance(status_fashion, dict):
                raise ImportDataError(f"卡池 {key} 的状态服装元数据无效")
            fashion_id = status_fashion.get("fashion_id")
            plate_count = status_fashion.get("color_plate_count")
            evolution_item_id = status_fashion.get("fashion_evolution_item_id")
            if (
                not isinstance(fashion_id, int)
                or isinstance(fashion_id, bool)
                or fashion_id <= 0
                or fashion_id in status_ids
                or not isinstance(plate_count, int)
                or isinstance(plate_count, bool)
                or not 0 <= plate_count <= 64
                or not isinstance(evolution_item_id, int)
                or isinstance(evolution_item_id, bool)
                or evolution_item_id < 0
            ):
                raise ImportDataError(f"卡池 {key} 的状态服装元数据无效")
            status_ids.add(fashion_id)

        suite_ids = pool.get("suite_fashion_ids", [])
        if (
            not _positive_int_list(suite_ids)
            or len(suite_ids) != len(set(suite_ids))
        ):
            raise ImportDataError(f"卡池 {key} 的 suite_fashion_ids 无效")
        if pool.get("suite_mapping_confidence") == "verified":
            if not suite_ids or status_ids != set(suite_ids):
                raise ImportDataError(f"卡池 {key} 的状态服装未完整覆盖套装")
            if not set(pool.get("main_fashion_ids", [])).issubset(suite_ids):
                raise ImportDataError(f"卡池 {key} 的主服装不在已核验套装中")

        piece_count = pool.get("piece_count")
        if piece_count is not None and (
            not isinstance(piece_count, int)
            or isinstance(piece_count, bool)
            or piece_count <= 0
        ):
            raise ImportDataError(f"卡池 {key} 的 piece_count 无效")
        marks = pool.get("piece_marks", [])
        if not isinstance(marks, list):
            raise ImportDataError(f"卡池 {key} 的 piece_marks 无效")
        piece_fashion_ids = pool.get("piece_fashion_ids", [])
        if (
            not _positive_int_list(piece_fashion_ids)
            or len(piece_fashion_ids) != len(set(piece_fashion_ids))
        ):
            raise ImportDataError(f"卡池 {key} 的 piece_fashion_ids 无效")
        slots: set[int] = set()
        for mark in marks:
            if not isinstance(mark, dict):
                raise ImportDataError(f"卡池 {key} 的部件标记无效")
            slot = mark.get("slot_index")
            fashion_ids = mark.get("fashion_ids")
            if (
                not isinstance(slot, int)
                or isinstance(slot, bool)
                or slot < 0
                or slot in slots
                or not _positive_int_list(fashion_ids)
            ):
                raise ImportDataError(f"卡池 {key} 的部件标记无效")
            slots.add(slot)

        if pool.get("piece_mapping_confidence") == "verified_complete":
            if (
                not isinstance(piece_count, int)
                or len(marks) != piece_count
                or slots != set(range(piece_count))
            ):
                raise ImportDataError(f"卡池 {key} 的完整部件映射自检失败")
            if (
                pool.get("suite_mapping_confidence") != "verified"
                and status_ids != set(piece_fashion_ids)
            ):
                raise ImportDataError(f"卡池 {key} 的状态服装未完整覆盖部件")
            geometry = pool.get("image_geometry")
            if not isinstance(geometry, dict):
                raise ImportDataError(f"卡池 {key} 缺少图片坐标数据")
            source_width = geometry.get("source_width")
            source_height = geometry.get("source_height")
            centers = geometry.get("slot_centers")
            if (
                not isinstance(source_width, int)
                or source_width <= 0
                or not isinstance(source_height, int)
                or source_height <= 0
                or not isinstance(centers, list)
                or len(centers) != piece_count
            ):
                raise ImportDataError(f"卡池 {key} 的图片坐标数据无效")
    normalized_catalog = dict(catalog)
    normalized_catalog["pools"] = pools
    normalized_catalog.pop("backgrounds", None)
    normalized_catalog.pop("background_pools", None)
    return normalized_catalog


def _validated_count_map(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ImportDataError(f"抽数证据的 {label} 无效")
    normalized: dict[str, int] = {}
    for raw_key, raw_count in value.items():
        if not isinstance(raw_key, str) or not raw_key:
            raise ImportDataError(f"抽数证据的 {label} 包含无效 key")
        if (
            not isinstance(raw_count, int)
            or isinstance(raw_count, bool)
            or raw_count < 0
            or raw_count > MAX_SAFE_INTEGER
        ):
            raise ImportDataError(f"抽数证据的 {label}[{raw_key}] 无效")
        normalized[raw_key] = raw_count
    return normalized


def _draw_counts_for_catalog(
    draw_evidence: Any, pools: list[dict[str, Any]]
) -> DrawCountImport:
    if not isinstance(draw_evidence, dict):
        return DrawCountImport({}, 0, 0, "none", False, "unobserved")

    status = str(draw_evidence.get("status") or "unobserved")
    evidence_level = str(draw_evidence.get("evidence_level") or "none")
    snapshot_usable = (
        status in {"observed_present", "observed_absent"}
        and draw_evidence.get("snapshot_complete") is True
        and draw_evidence.get("completeness") is True
        and draw_evidence.get("scope") == "server_pool_snapshot"
    )
    if not snapshot_usable:
        return DrawCountImport({}, 0, 0, evidence_level, False, status)

    if evidence_level not in SUPPORTED_DRAW_EVIDENCE_LEVELS:
        raise ImportDataError(
            f"完整737抽数快照的证据级别无效：{evidence_level}"
        )
    evidence_sources = draw_evidence.get("evidence_sources")
    if (
        not isinstance(evidence_sources, list)
        or not evidence_sources
        or any(not isinstance(source, str) or not source for source in evidence_sources)
    ):
        raise ImportDataError("完整737抽数快照的证据来源无效")
    unique_sources = set(evidence_sources)
    candidate_sources = {
        source for source in unique_sources if source.endswith("candidate")
    }
    if candidate_sources == unique_sources:
        derived_evidence_level = "candidate"
    elif candidate_sources:
        derived_evidence_level = "mixed"
    elif unique_sources == {"direct"}:
        derived_evidence_level = "direct"
    else:
        derived_evidence_level = "other"
    if derived_evidence_level != evidence_level:
        raise ImportDataError("完整737抽数快照的证据级别与来源不一致")
    if draw_evidence.get("source_field") != DRAW_SOURCE_FIELD:
        raise ImportDataError("完整737抽数快照的来源字段无效")
    if draw_evidence.get("evidence_messages") != 1:
        raise ImportDataError("抽数导入只接受单个结构完整的737响应")
    duplicate_pool_ids = draw_evidence.get("duplicate_pool_ids")
    if duplicate_pool_ids != []:
        raise ImportDataError("完整737抽数快照包含重复卡池 ID")

    by_pool_id = _validated_count_map(
        draw_evidence.get("by_pool_id"), "by_pool_id"
    )
    canonical_by_pool_id: dict[str, int] = {}
    for pool_id, count in by_pool_id.items():
        try:
            numeric_pool_id = int(pool_id, 10)
        except ValueError as error:
            raise ImportDataError(f"抽数证据包含无效卡池 ID：{pool_id}") from error
        if (
            numeric_pool_id <= 0
            or numeric_pool_id > MAX_SAFE_INTEGER
            or str(numeric_pool_id) != pool_id
        ):
            raise ImportDataError(f"抽数证据包含无效卡池 ID：{pool_id}")
        canonical_by_pool_id[pool_id] = count

    observed_pool_count = draw_evidence.get("observed_pool_count")
    if (
        not isinstance(observed_pool_count, int)
        or isinstance(observed_pool_count, bool)
        or observed_pool_count != len(canonical_by_pool_id)
    ):
        raise ImportDataError("完整737抽数快照的卡池数量自检失败")
    if status == "observed_absent" and canonical_by_pool_id:
        raise ImportDataError("空737抽数快照不应包含卡池数据")

    catalog_keys_by_id: dict[str, list[str]] = {}
    ordinary_keys: set[str] = set()
    for pool in pools:
        if _is_background_pool(pool):
            continue
        key = pool["key"]
        ordinary_keys.add(key)
        lottery_pool_id = pool.get("lottery_pool_id")
        if lottery_pool_id is not None:
            catalog_keys_by_id.setdefault(str(lottery_pool_id), []).append(key)

    expected_by_pool_key: dict[str, int] = {}
    expected_unmapped: dict[str, int] = {}
    for pool_id, count in canonical_by_pool_id.items():
        mapped_keys = catalog_keys_by_id.get(pool_id)
        if not mapped_keys:
            expected_unmapped[pool_id] = count
            continue
        for key in mapped_keys:
            expected_by_pool_key[key] = count

    report_by_pool_key = _validated_count_map(
        draw_evidence.get("by_pool_key"), "by_pool_key"
    )
    unknown_keys = set(report_by_pool_key) - ordinary_keys
    if unknown_keys:
        raise ImportDataError(
            "抽数证据包含当前卡池目录不存在的 key："
            + "、".join(sorted(unknown_keys)[:8])
        )
    if report_by_pool_key != expected_by_pool_key:
        raise ImportDataError("报告抽数映射与当前卡池目录不一致，请重新生成报告")

    report_unmapped = _validated_count_map(
        draw_evidence.get("unmapped_by_pool_id"), "unmapped_by_pool_id"
    )
    if report_unmapped != expected_unmapped:
        raise ImportDataError("报告未映射抽数与当前卡池目录不一致，请重新生成报告")

    mapping_summary = draw_evidence.get("pool_id_to_key_catalog")
    if (
        not isinstance(mapping_summary, dict)
        or mapping_summary.get("status") != "loaded"
        or mapping_summary.get("mapped_pool_count") != len(expected_by_pool_key)
        or mapping_summary.get("unmapped_pool_count") != len(expected_unmapped)
    ):
        raise ImportDataError("完整737抽数快照的目录映射摘要自检失败")

    return DrawCountImport(
        by_pool_key=expected_by_pool_key,
        observed_source_pool_count=len(canonical_by_pool_id),
        unmapped_source_pool_count=len(expected_unmapped),
        evidence_level=evidence_level,
        snapshot_usable=True,
        status=status,
    )


def _wardrobe_evidence_from_report(report: dict[str, Any]) -> WardrobeEvidence:
    coverage = report.get("data_coverage")
    if not isinstance(coverage, dict):
        raise ImportDataError("报告缺少 data_coverage")
    wardrobe = coverage.get("wardrobe_presence")
    if not isinstance(wardrobe, dict):
        raise ImportDataError("报告缺少 wardrobe_presence")

    if not bool(wardrobe.get("snapshot_complete")) or not bool(
        wardrobe.get("standard_wardrobe_complete")
    ):
        raise ImportDataError("衣柜快照不完整，拒绝生成会覆盖小程序账号的导入码")

    fashions = wardrobe.get("fashions")
    if not isinstance(fashions, list):
        raise ImportDataError("报告缺少衣柜 fashions 列表")
    owned: set[int] = set()
    fashion_records: dict[int, dict[str, int | None]] = {}
    for fashion in fashions:
        if not isinstance(fashion, dict) or fashion.get("kind") != "standard":
            continue
        if fashion.get("owned") is not True or fashion.get("ui_owned") is not True:
            continue
        fashion_id = fashion.get("fashion_index")
        if isinstance(fashion_id, int) and fashion_id > 0:
            owned.add(fashion_id)
            fashion_records[fashion_id] = {
                "fashion_index": fashion_id,
                "unlocked_plate_count": _ensure_int_or_none(
                    fashion.get("unlocked_plate_count")
                ),
                "unlocked_plate_mask": _ensure_int_or_none(
                    fashion.get("unlocked_plate_mask")
                ),
                "evolution": _ensure_int_or_none(fashion.get("evolution")),
                "modeling_unlock_mask": _ensure_int_or_none(
                    fashion.get("modeling_unlock_mask")
                ),
            }

    expected_count = wardrobe.get("standard_fashion_count")
    if not isinstance(expected_count, int) or expected_count < 0:
        raise ImportDataError("报告缺少标准衣柜数量")
    if len(owned) != expected_count:
        raise ImportDataError(
            f"衣柜数量自检失败：列表 {len(owned)}，报告摘要 {expected_count}"
        )

    catalog = wardrobe.get("catalog")
    if not isinstance(catalog, dict) or catalog.get("status") != "loaded":
        raise ImportDataError("报告没有可核验的静态服装目录")
    catalog_sha256 = catalog.get("sha256")
    catalog_fashion_count = catalog.get("fashion_catalog_count")
    if not isinstance(catalog_sha256, str) or not isinstance(
        catalog_fashion_count, int
    ):
        raise ImportDataError("报告的静态服装目录版本无效")

    return WardrobeEvidence(
        generated_at=str(report.get("generated_at") or ""),
        owned_fashion_ids=frozenset(owned),
        fashion_records=fashion_records,
        standard_fashion_count=expected_count,
        catalog_sha256=catalog_sha256.upper(),
        catalog_fashion_count=catalog_fashion_count,
    )


def _main_item_owned(pool: dict[str, Any], owned: frozenset[int]) -> bool:
    if pool.get("mapping_confidence") not in VERIFIED_MAPPING_LEVELS:
        return False
    fashion_ids = tuple(pool.get("main_fashion_ids", []))
    if not fashion_ids:
        return False
    if pool.get("main_requirement", "any") == "all":
        return all(fashion_id in owned for fashion_id in fashion_ids)
    return any(fashion_id in owned for fashion_id in fashion_ids)


def _owned_marks(
    pool: dict[str, Any], owned: frozenset[int]
) -> list[dict[str, Any]]:
    return [
        mark
        for mark in sorted(
            pool.get("piece_marks", []), key=lambda value: value["slot_index"]
        )
        if any(fashion_id in owned for fashion_id in mark["fashion_ids"])
    ]


def _fashion_has_full_colors(
    record: dict[str, int | None] | None, expected_plate_count: int
) -> bool:
    if record is None:
        return False
    unlocked_mask = record.get("unlocked_plate_mask")
    return (
        expected_plate_count > 1
        and record.get("unlocked_plate_count") == expected_plate_count
        and isinstance(unlocked_mask, int)
        and unlocked_mask >= 0
        and unlocked_mask.bit_count() == expected_plate_count
    )


def _fashion_evolution_at_least(
    record: dict[str, int | None] | None, minimum: int
) -> bool:
    if record is None:
        return False
    value = record.get("evolution")
    return value is not None and value >= minimum


def _expandable_status_fashions(pool: dict[str, Any]) -> list[dict[str, int]]:
    return [
        status_fashion
        for status_fashion in pool.get("status_fashions", [])
        if status_fashion["fashion_evolution_item_id"] > 0
        and status_fashion["color_plate_count"] > 1
    ]


def _main_status_fashions(pool: dict[str, Any]) -> list[dict[str, int]]:
    main_ids = set(pool.get("main_fashion_ids", []))
    return [
        status_fashion
        for status_fashion in _expandable_status_fashions(pool)
        if status_fashion["fashion_id"] in main_ids
    ]


def _status_metadata_complete(pool: dict[str, Any]) -> bool:
    status_ids = {
        status_fashion["fashion_id"]
        for status_fashion in pool.get("status_fashions", [])
    }
    if pool.get("suite_mapping_confidence") == "verified":
        suite_ids = set(pool.get("suite_fashion_ids", []))
        return bool(suite_ids) and status_ids == suite_ids
    if pool.get("piece_mapping_confidence") == "verified_complete":
        piece_ids = set(pool.get("piece_fashion_ids", []))
        return bool(piece_ids) and status_ids == piece_ids
    return False


def _all_evolution_at_least(
    status_fashions: list[dict[str, int]],
    fashion_records: dict[int, dict[str, int | None]],
    minimum: int,
) -> bool:
    return bool(status_fashions) and all(
        _fashion_evolution_at_least(
            fashion_records.get(status_fashion["fashion_id"]), minimum
        )
        for status_fashion in status_fashions
    )


def _all_full_colors(
    status_fashions: list[dict[str, int]],
    fashion_records: dict[int, dict[str, int | None]],
) -> bool:
    return bool(status_fashions) and all(
        _fashion_has_full_colors(
            fashion_records.get(status_fashion["fashion_id"]),
            status_fashion["color_plate_count"],
        )
        for status_fashion in status_fashions
    )


def _infer_pool_status(
    pool: dict[str, Any],
    *,
    owned: frozenset[int],
    fashion_records: dict[int, dict[str, int | None]],
    full_set: bool = False,
) -> int:
    if not _main_item_owned(pool, owned) or not _status_metadata_complete(pool):
        return STATUS_TO_CODE["未抽齐"]

    expandable = _expandable_status_fashions(pool)
    main_expandable = _main_status_fashions(pool)
    main_expanded = _all_evolution_at_least(
        main_expandable, fashion_records, 1
    )
    main_thousand = _all_evolution_at_least(
        main_expandable, fashion_records, 2
    )

    if not full_set:
        return (
            STATUS_TO_CODE["扩裙"]
            if main_expanded
            else STATUS_TO_CODE["有裙"]
        )

    all_expanded = _all_evolution_at_least(expandable, fashion_records, 1)
    all_thousand = _all_evolution_at_least(expandable, fashion_records, 2)
    all_full_colors = _all_full_colors(expandable, fashion_records)

    if all_thousand:
        return STATUS_TO_CODE["千幻"]
    if all_full_colors and main_thousand:
        return STATUS_TO_CODE["特姿裙幻"]
    if all_full_colors:
        return STATUS_TO_CODE["特姿"]
    if all_expanded and main_thousand:
        return STATUS_TO_CODE["全扩裙幻"]
    if all_expanded:
        return STATUS_TO_CODE["全扩"]
    if main_thousand:
        return STATUS_TO_CODE["全齐裙幻"]
    if main_expanded:
        return STATUS_TO_CODE["扩裙"]
    return STATUS_TO_CODE["全齐"]


def _full_set_owned(
    pool: dict[str, Any], owned_marks: list[dict[str, Any]], owned: frozenset[int]
) -> bool:
    piece_count = pool.get("piece_count")
    if (
        pool.get("piece_mapping_confidence") == "verified_complete"
        and isinstance(piece_count, int)
        and len(owned_marks) == piece_count
    ):
        return True

    # Exact static suite membership is independent of whether the old detail
    # image and its configured counter are still available.
    if pool.get("suite_mapping_confidence") == "verified":
        suite_ids = pool.get("suite_fashion_ids", [])
        return bool(suite_ids) and all(fashion_id in owned for fashion_id in suite_ids)
    return False


def _scaled_coordinate(value: Any, pool_key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ImportDataError(f"卡池 {pool_key} 的槽位中心无效")
    try:
        decimal = Decimal(str(value))
    except InvalidOperation as error:
        raise ImportDataError(f"卡池 {pool_key} 的槽位中心无效") from error
    if not decimal.is_finite() or not 0 <= decimal <= 1:
        raise ImportDataError(f"卡池 {pool_key} 的槽位中心无效")
    scaled = decimal * COORDINATE_SCALE
    if scaled != scaled.to_integral_value():
        raise ImportDataError(f"卡池 {pool_key} 的槽位中心精度超过 6 位小数")
    return int(scaled)


def _round_half_up_ratio(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ImportDataError("详情图几何尺寸无效")
    return (numerator + denominator // 2) // denominator


def _mark_coordinates(
    pool: dict[str, Any], marks: list[dict[str, Any]], target_width: int
) -> tuple[tuple[int, int], ...]:
    if not marks:
        return ()
    geometry = pool["image_geometry"]
    source_width = int(geometry["source_width"])
    source_height = int(geometry["source_height"])
    if source_width <= 0 or source_height <= 0:
        raise ImportDataError(f"卡池 {pool['key']} 的详情图尺寸无效")
    centers = geometry["slot_centers"]

    marker_size = source_width // 20
    points: list[tuple[int, int]] = []
    for mark in marks:
        center = centers[mark["slot_index"]]
        if (
            not isinstance(center, list)
            or len(center) != 2
        ):
            raise ImportDataError(f"卡池 {pool['key']} 的槽位中心无效")
        center_x = _scaled_coordinate(center[0], pool["key"])
        center_y = _scaled_coordinate(center[1], pool["key"])
        x = _round_half_up_ratio(
            2 * center_x * target_width - marker_size * COORDINATE_SCALE,
            2 * COORDINATE_SCALE,
        )
        y = _round_half_up_ratio(
            2 * center_y * source_height * target_width
            - marker_size * COORDINATE_SCALE * source_width,
            2 * COORDINATE_SCALE * source_width,
        )
        points.append((x, y))
    return tuple(points)


def validate_import_code(
    code: str,
    known_pool_keys: set[str] | None = None,
    known_background_keys: set[str] | None = None,
    *,
    require_all_known_keys: bool = False,
) -> None:
    try:
        rows = json.loads(code)
    except json.JSONDecodeError as error:
        raise ImportDataError(f"导入码不是有效 JSON：{error}") from error
    if not isinstance(rows, list):
        raise ImportDataError("导入码根节点必须是数组")

    seen: set[str] = set()
    for position, row in enumerate(rows):
        if not isinstance(row, list) or len(row) not in {2, 3, 5}:
            raise ImportDataError(f"导入码第 {position + 1} 条结构无效")
        if len(row) == 2:
            key, owned = row
            if not isinstance(key, str) or not key:
                raise ImportDataError(f"导入码第 {position + 1} 条缺少卡池 key")
            if key in seen:
                raise ImportDataError(f"导入码中卡池重复：{key}")
            seen.add(key)
            if known_pool_keys is not None and key not in known_pool_keys:
                raise ImportDataError(f"导入码包含未知卡池：{key}")
            if known_background_keys is not None and key not in known_background_keys:
                raise ImportDataError(f"普通卡池不能使用背景行：{key}")
            if (
                not isinstance(owned, int)
                or isinstance(owned, bool)
                or owned not in {0, 1}
            ):
                raise ImportDataError(f"背景 {key} 的所有权标记无效")
            continue
        key, draw_count, status_code = row[:3]
        if not isinstance(key, str) or not key:
            raise ImportDataError(f"导入码第 {position + 1} 条缺少卡池 key")
        if key in seen:
            raise ImportDataError(f"导入码中卡池重复：{key}")
        seen.add(key)
        if known_pool_keys is not None and key not in known_pool_keys:
            raise ImportDataError(f"导入码包含未知卡池：{key}")
        if known_background_keys is not None and key in known_background_keys:
            raise ImportDataError(f"背景不能使用普通卡池行：{key}")
        if (
            not isinstance(draw_count, int)
            or isinstance(draw_count, bool)
            or draw_count < 0
            or draw_count > MAX_SAFE_INTEGER
        ):
            raise ImportDataError(f"卡池 {key} 的抽数无效")
        if (
            not isinstance(status_code, int)
            or isinstance(status_code, bool)
            or status_code not in VALID_STATUS_CODES
        ):
            raise ImportDataError(f"卡池 {key} 的状态码无效：{status_code}")
        if len(row) == 5:
            if row[3] != "":
                raise ImportDataError(f"卡池 {key} 的备注必须为空字符串")
            points = row[4]
            if (
                not isinstance(points, list)
                or len(points) < 2
                or len(points) % 2
                or any(
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    for value in points
                )
            ):
                raise ImportDataError(f"卡池 {key} 的标记坐标无效")

    if require_all_known_keys:
        if known_pool_keys is None:
            raise ImportDataError("完整导入码校验需要卡池目录")
        missing = sorted(known_pool_keys - seen)
        if missing:
            preview = "、".join(missing[:8])
            suffix = "……" if len(missing) > 8 else ""
            raise ImportDataError(
                f"导入码缺少 {len(missing)} 个卡池：{preview}{suffix}"
            )


def generate_import_code_from_report(
    report: dict[str, Any],
    catalog_path: Path,
    *,
    target_image_width_px: int = 261,
    background_ownership: dict[str, bool | int] | None = None,
    allow_unresolved_status: bool = False,
) -> ImportResult:
    """Generate a complete WeChat import code from a validated report mapping."""
    if not isinstance(report, dict):
        raise ImportDataError("报告根节点必须是对象")
    if (
        not isinstance(target_image_width_px, int)
        or isinstance(target_image_width_px, bool)
        or not 120 <= target_image_width_px <= 1200
    ):
        raise ImportDataError("详情图显示宽度必须是 120 到 1200 的整数")

    catalog = load_pool_catalog(catalog_path)
    evidence = _wardrobe_evidence_from_report(report)
    coverage = report.get("data_coverage", {})
    draw_evidence = (
        coverage.get("draw_count") if isinstance(coverage, dict) else None
    )
    photo_ids, photo_snapshot_ok = _photo_snapshot_ids(
        coverage.get("photo_info") if isinstance(coverage, dict) else None
    )
    game_catalog = catalog["game_catalog"]
    catalog_sha256 = str(game_catalog["sha256"]).upper()
    if evidence.catalog_sha256 != catalog_sha256:
        raise ImportDataError("报告与卡池目录使用的游戏服装版本不同，拒绝生成")
    catalog_fashion_count = game_catalog.get("fashion_catalog_count")
    if (
        isinstance(catalog_fashion_count, int)
        and evidence.catalog_fashion_count != catalog_fashion_count
    ):
        raise ImportDataError("报告与卡池目录的服装总数不同，拒绝生成")

    pools = catalog["pools"]
    draw_import = _draw_counts_for_catalog(draw_evidence, pools)
    known_keys = {pool["key"] for pool in pools}
    known_background_keys = {
        pool["key"] for pool in pools if _is_background_pool(pool)
    }
    records: list[ImportRecord] = []
    complete_piece_pool_count = 0
    unresolved_piece_keys: list[str] = []
    mapped_piece_count = 0
    marked_owned_piece_count = 0
    owned_main_count = 0
    full_set_count = 0
    missing_main_count = 0
    unresolved_status_keys: list[str] = []
    background_pool_count = 0
    observed_draw_count = 0

    for pool in pools:
        is_background = _is_background_pool(pool)
        if is_background:
            background_pool_count += 1
            scene_ids = pool.get("scene_ids", [])
            if pool.get("unavailable_in_installed_version") is True and scene_ids == []:
                value = 0
            elif (
                pool.get("mapping_confidence") in VERIFIED_MAPPING_LEVELS
                and isinstance(scene_ids, list)
                and bool(scene_ids)
            ):
                if not photo_snapshot_ok:
                    raise ImportDataError("背景照片命令637快照不完整，拒绝推导背景所有权")
                value = int(any(scene_id in photo_ids for scene_id in scene_ids))
            elif background_ownership is not None and pool.get("key") in background_ownership:
                value = background_ownership[pool["key"]]
                if value not in (0, 1, False, True):
                    raise ImportDataError(f"背景 {pool['key']} 的所有权必须是 0/1")
            else:
                raise ImportDataError(f"背景 {pool.get('key', '')} 的映射或所有权未知，拒绝生成")
            records.append(ImportRecord(pool_key=pool["key"], draw_count=int(bool(value)), status_code=0, background=True))
            continue
        complete_piece_mapping = (
            pool.get("piece_mapping_confidence") == "verified_complete"
        )
        if complete_piece_mapping:
            complete_piece_pool_count += 1
            mapped_piece_count += len(pool.get("piece_marks", []))
        else:
            unresolved_piece_keys.append(pool["key"])

        owned_marks = _owned_marks(pool, evidence.owned_fashion_ids)
        mark_points = (
            _mark_coordinates(pool, owned_marks, target_image_width_px)
            if complete_piece_mapping
            else ()
        )
        marked_owned_piece_count += len(mark_points)

        main_known = pool.get("mapping_confidence") in VERIFIED_MAPPING_LEVELS
        main_owned = _main_item_owned(pool, evidence.owned_fashion_ids)
        if main_owned:
            owned_main_count += 1

        full_set = _full_set_owned(
            pool, owned_marks, evidence.owned_fashion_ids
        )
        if full_set:
            full_set_count += 1
        status_metadata_complete = _status_metadata_complete(pool)
        if main_owned and status_metadata_complete:
            status_code = _infer_pool_status(
                pool,
                owned=evidence.owned_fashion_ids,
                fashion_records=evidence.fashion_records,
                full_set=full_set,
            )
        else:
            if main_owned and not status_metadata_complete:
                unresolved_status_keys.append(pool["key"])
            if main_known:
                if not main_owned:
                    missing_main_count += 1
            else:
                unresolved_status_keys.append(pool["key"])
            status_code = STATUS_TO_CODE["未抽齐"]

        draw_count = draw_import.by_pool_key.get(pool["key"], 0)
        if pool["key"] in draw_import.by_pool_key:
            observed_draw_count += 1

        records.append(
            ImportRecord(
                pool_key=pool["key"],
                draw_count=draw_count,
                status_code=status_code,
                mark_points=mark_points,
            )
        )

    if unresolved_status_keys and not allow_unresolved_status:
        raise ImportDataError(
            "以下普通卡池缺少完整状态证据，拒绝生成覆盖式导入码："
            + "、".join(unresolved_status_keys)
        )

    code = json.dumps(
        [record.to_row() for record in records],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    validate_import_code(
        code,
        known_keys,
        known_background_keys,
        require_all_known_keys=True,
    )

    ordinary_pool_count = len(records) - background_pool_count
    warnings = [
        "备注全部为空；逐件标记只来自完整衣柜与已核验的详情图槽位。",
        "扩裙、全扩、特姿、裙幻组合与千幻由静态色盘容量、"
        "衣柜色盘位图和服装 evolution 阶段共同推断；不可染部件不参与染色阶段判定。",
    ]
    if draw_import.snapshot_usable:
        warnings.insert(
            0,
            f"已从单个结构完整的737服务器响应写入 {observed_draw_count}/{ordinary_pool_count} "
            f"个普通池的累计抽数；其余 {ordinary_pool_count - observed_draw_count} 个池"
            "未在本次响应中观测到或没有可核验的版本映射，保留 0。",
        )
        if draw_import.evidence_level == "candidate":
            warnings.insert(
                1,
                "737抽数来自结构核验的候选协议封装：字段5同时得到游戏运行时代码读取"
                "和抓包结构支持，但不是直接消息证据。",
            )
        elif draw_import.evidence_level == "mixed":
            warnings.insert(
                1,
                "737抽数包含直接与候选协议证据，已通过单快照和目录一致性校验。",
            )
        if draw_import.unmapped_source_pool_count:
            warnings.append(
                f"{draw_import.unmapped_source_pool_count} 个服务器卡池没有小程序普通池映射，"
                "未写入导入码。"
            )
    else:
        warnings.insert(
            0,
            "未取得可用于导入的单个结构完整737服务器响应；普通池抽数保留 0，"
            "这不代表实际抽数为 0。",
        )
    if ordinary_pool_count - observed_draw_count:
        warnings.append(
            "小程序导入会覆盖当前账号；保留 0 的未观测普通池也会覆盖原记录，"
            "导入前请先导出现有记录。"
        )
    if unresolved_piece_keys:
        warnings.append(
            f"{len(unresolved_piece_keys)} 个旧池缺少可核验的详情图槽位，"
            "已保留套装状态但未写入猜测坐标。"
        )
    if unresolved_status_keys:
        warnings.append(
            f"{len(unresolved_status_keys)} 个旧池缺少可核验主套映射，"
            "状态按未抽齐保守输出。"
        )

    return ImportResult(
        code=code,
        records=tuple(records),
        catalog_pool_count=len(pools),
        complete_piece_pool_count=complete_piece_pool_count,
        unresolved_piece_pool_count=len(unresolved_piece_keys),
        mapped_piece_count=mapped_piece_count,
        marked_owned_piece_count=marked_owned_piece_count,
        owned_main_count=owned_main_count,
        full_set_count=full_set_count,
        missing_main_count=missing_main_count,
        unresolved_status_pool_count=len(unresolved_status_keys),
        target_image_width_px=target_image_width_px,
        warnings=tuple(warnings),
        unobserved_draw_count=ordinary_pool_count - observed_draw_count,
        observed_draw_pool_count=observed_draw_count,
        background_pool_count=background_pool_count,
        observed_draw_source_pool_count=draw_import.observed_source_pool_count,
        unmapped_server_draw_pool_count=draw_import.unmapped_source_pool_count,
        draw_evidence_level=draw_import.evidence_level,
    )
