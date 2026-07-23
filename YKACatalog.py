"""Game fashion catalog parser and immutable compact-catalog builder."""

from __future__ import annotations

import hashlib
import json
import re
import struct
import zlib
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterator


PACKAGE_MAGIC = bytes.fromhex("ef23ca4d")
PACKAGE_HEADER_BYTES = 300
# Current 2026-07-21 package layout prepends a small v1 table before the
# Fashion and FashionSuite BCFG streams.
PACKAGE_LEADING_STREAMS = 1
FASHION_SCHEMA_INDEX = 3637
FASHION_SUITE_SCHEMA_INDEX = 990
EXPECTED_FASHION_TABLE = (9, 9530)
EXPECTED_FASHION_SUITE_TABLE = (2, 943)

FASHION_TYPE_NAMES = {
    1: "发型",
    2: "连衣裙",
    3: "外套",
    4: "上衣",
    5: "下装",
    6: "袜子",
    7: "鞋子",
    8: "帽子",
    9: "发饰",
    10: "面饰",
    11: "耳饰",
    12: "颈饰",
    14: "腕饰",
    15: "手套",
    16: "戒指",
    17: "手持物",
    18: "翅膀",
    19: "尾巴",
    20: "背饰",
    21: "纹身",
    22: "眼影",
    23: "眼线",
    24: "脚链",
    25: "斜跨",
    26: "悬浮",
    27: "眉妆",
    28: "底妆",
    29: "睫毛",
    30: "美瞳",
    31: "唇妆",
    32: "纹面",
    33: "指甲",
    34: "腮红",
    35: "座驾",
}


class CatalogDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class FashionCatalog:
    entries: dict[int, dict[str, Any]]
    metadata: dict[str, Any]
    suites: dict[int, dict[str, Any]] = field(default_factory=dict)


def _read_uint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise EOFError("missing BCFG compact uint")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    if first < 0xC0:
        end = offset + 2
        if end > len(data):
            raise EOFError("truncated two-byte BCFG compact uint")
        return ((first & 0x3F) << 8) | data[offset + 1], end
    if first < 0xE0:
        end = offset + 3
        if end > len(data):
            raise EOFError("truncated three-byte BCFG compact uint")
        return (
            ((first & 0x1F) << 16)
            | (data[offset + 1] << 8)
            | data[offset + 2],
            end,
        )
    if first < 0xF0:
        end = offset + 4
        if end > len(data):
            raise EOFError("truncated four-byte BCFG compact uint")
        return (
            ((first & 0x0F) << 24)
            | int.from_bytes(data[offset + 1 : end], "big"),
            end,
        )
    if first == 0xF0:
        end = offset + 5
        if end > len(data):
            raise EOFError("truncated five-byte BCFG compact uint")
        return int.from_bytes(data[offset + 1 : end], "big"), end
    raise CatalogDecodeError(f"invalid BCFG compact uint prefix 0x{first:02x}")


def _read_octets(data: bytes, offset: int) -> tuple[bytes, int]:
    length, offset = _read_uint(data, offset)
    end = offset + length
    if end > len(data):
        raise EOFError("truncated BCFG octets")
    return data[offset:end], end


def _read_text(data: bytes, offset: int) -> tuple[str, int]:
    value, offset = _read_octets(data, offset)
    return value.decode("utf-8"), offset


def _inflate_at(raw: bytes, offset: int) -> tuple[bytes, int]:
    decoder = zlib.decompressobj()
    try:
        output = decoder.decompress(raw[offset:]) + decoder.flush()
    except zlib.error as error:
        raise CatalogDecodeError(f"invalid zlib stream at {offset}: {error}") from error
    if not decoder.eof:
        raise CatalogDecodeError(f"truncated zlib stream at {offset}")
    used = len(raw) - offset - len(decoder.unused_data)
    return output, offset + used


def _parse_table(
    blob: bytes,
    *,
    index_offset: int,
    expected: tuple[int, int],
    table_name: bytes,
) -> tuple[bytes, list[tuple[int, int]]]:
    if len(blob) < 20 or blob[:2] != b"cx":
        raise CatalogDecodeError("BCFG table has no cx header")
    version, count, data_length, schema_length = struct.unpack_from(
        ">HIIH", blob, 2
    )
    if (version, count) != expected:
        raise CatalogDecodeError(
            f"unexpected BCFG version/count: {(version, count)} != {expected}"
        )
    data_end = 20 + data_length
    schema_end = data_end + schema_length
    if schema_end > len(blob):
        raise CatalogDecodeError("truncated BCFG data or schema")
    row_data = blob[20:data_end]
    schema = blob[data_end:schema_end]
    if table_name not in schema[:128]:
        raise CatalogDecodeError(f"unexpected BCFG schema for {table_name!r}")
    offset = index_offset
    index: list[tuple[int, int]] = []
    try:
        for _ in range(count + 1):
            key, offset = _read_uint(schema, offset)
            row_offset, offset = _read_uint(schema, offset)
            index.append((key, row_offset))
    except EOFError as error:
        raise CatalogDecodeError("truncated BCFG row index") from error
    if index[-1] != (data_length, data_length):
        raise CatalogDecodeError("invalid BCFG row-index sentinel")
    if index[0][1] != 0:
        raise CatalogDecodeError("BCFG first row does not start at offset zero")
    if any(
        index[i][0] >= index[i + 1][0] for i in range(len(index) - 2)
    ):
        raise CatalogDecodeError("BCFG row keys are not strictly increasing")
    if any(index[i][1] >= index[i + 1][1] for i in range(len(index) - 1)):
        raise CatalogDecodeError("BCFG row offsets are not strictly increasing")
    return row_data, index


def _rows(
    data: bytes, index: list[tuple[int, int]]
) -> Iterator[tuple[int, bytes]]:
    for position, (key, start) in enumerate(index[:-1]):
        yield key, data[start : index[position + 1][1]]


def _parse_fashion(fashion_index: int, row: bytes) -> dict[str, Any]:
    # The exact table version/count gate above pins this stable prefix through
    # color_plates. Later fields are intentionally outside the report schema.
    offset = 0
    numbers: list[int] = []
    try:
        for _ in range(20):
            value, offset = _read_uint(row, offset)
            numbers.append(value)
        name, offset = _read_text(row, offset)
        quality, offset = _read_uint(row, offset)
        debug_name, offset = _read_text(row, offset)
        _, offset = _read_uint(row, offset)  # drop_id
        for _ in range(3):  # drop_desc, show_anim, show_emotion
            _, offset = _read_octets(row, offset)
        _, offset = _read_uint(row, offset)  # stand_pose_type
        for _ in range(2):  # hand_pose, params
            _, offset = _read_octets(row, offset)
        _, offset = _read_uint(row, offset)  # test_lv
        for _ in range(3):  # show_dialogue1..3
            _, offset = _read_octets(row, offset)
        _, offset = _read_uint(row, offset)  # newgot_tip
        _, offset = _read_octets(row, offset)  # details
        _, offset = _read_uint(row, offset)  # decompose_reward_id
        _, offset = _read_uint(row, offset)  # gmt_funccode
        dye_num, offset = _read_uint(row, offset)
        _, offset = _read_uint(row, offset)  # old_dye_num
        _, offset = _read_uint(row, offset)  # special_color_plate_id
        _, offset = _read_uint(row, offset)  # use_special_color_plate_allcolor
        packed_color_plates, offset = _read_octets(row, offset)
        color_plate_count, plate_offset = _read_uint(packed_color_plates, 0)
        for _ in range(color_plate_count):
            _, plate_offset = _read_octets(packed_color_plates, plate_offset)
        if plate_offset != len(packed_color_plates):
            raise CatalogDecodeError("color_plates vector contains trailing bytes")
    except (EOFError, UnicodeDecodeError, CatalogDecodeError) as error:
        raise CatalogDecodeError(
            f"unable to parse fashion row {fashion_index}: {error}"
        ) from error
    fashion_type = numbers[0]
    return {
        "fashion_index": fashion_index,
        "name": name,
        "fashion_type": fashion_type,
        "part": FASHION_TYPE_NAMES.get(fashion_type, f"未知({fashion_type})"),
        "quality": quality,
        "debug_name": debug_name,
        "decompose_group_id": numbers[5],
        "fashion_evolution_item_id": numbers[3],
        "evolution_item_num": numbers[4],
        "dye_num": dye_num,
        "color_plate_count": color_plate_count,
        "is_home_fashion": bool(numbers[16]),
        "occasion_type_mask": numbers[18],
        "sort_index": numbers[19],
        "suites": [],
    }


def _parse_suite(suite_id: int, row: bytes) -> dict[str, Any]:
    offset = 0
    try:
        name, offset = _read_text(row, offset)
        suite_type, offset = _read_uint(row, offset)
        icon_id, offset = _read_uint(row, offset)
        for _ in range(6):
            _, offset = _read_octets(row, offset)
        for _ in range(3):
            _, offset = _read_uint(row, offset)
        quality, offset = _read_uint(row, offset)
        packed_items, offset = _read_octets(row, offset)
        item_offset = 0
        item_count, item_offset = _read_uint(packed_items, item_offset)
        items: list[tuple[int, int]] = []
        for _ in range(item_count):
            raw_item, item_offset = _read_octets(packed_items, item_offset)
            item_type, element_offset = _read_uint(raw_item, 0)
            item_id, element_offset = _read_uint(raw_item, element_offset)
            if element_offset != len(raw_item):
                raise CatalogDecodeError("suite item contains trailing bytes")
            items.append((item_type, item_id))
        if item_offset != len(packed_items):
            raise CatalogDecodeError("suite item vector contains trailing bytes")
        main_fashion_id, offset = _read_uint(row, offset)
    except (EOFError, UnicodeDecodeError) as error:
        raise CatalogDecodeError(
            f"unable to parse suite row {suite_id}: {error}"
        ) from error
    return {
        "suite_id": suite_id,
        "suite_name": name,
        "suite_type": suite_type,
        "quality": quality,
        "icon_id": icon_id,
        "main_fashion_id": main_fashion_id,
        "items": items,
    }


def _inflate_current_catalog_tables(raw: bytes) -> tuple[bytes, bytes, int]:
    """Read the fixed table order used by the currently installed game build."""
    offset = PACKAGE_HEADER_BYTES
    for _ in range(PACKAGE_LEADING_STREAMS):
        _, offset = _inflate_at(raw, offset)
    fashion_blob, offset = _inflate_at(raw, offset)
    suite_blob, package_end = _inflate_at(raw, offset)
    return fashion_blob, suite_blob, package_end


def load_fashion_catalog(path: Path) -> FashionCatalog:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CatalogDecodeError(f"unable to read {path}: {error}") from error
    if len(raw) < PACKAGE_HEADER_BYTES or raw[:4] != PACKAGE_MAGIC:
        raise CatalogDecodeError("data.png has an unexpected package header")
    if int.from_bytes(raw[4:12], "little") != len(raw):
        raise CatalogDecodeError("data.png declared length does not match file size")

    fashion_blob, suite_blob, suite_end = _inflate_current_catalog_tables(raw)
    fashion_data, fashion_index = _parse_table(
        fashion_blob,
        index_offset=FASHION_SCHEMA_INDEX,
        expected=EXPECTED_FASHION_TABLE,
        table_name=b"FASHION_ESSENCE",
    )
    suite_data, suite_index = _parse_table(
        suite_blob,
        index_offset=FASHION_SUITE_SCHEMA_INDEX,
        expected=EXPECTED_FASHION_SUITE_TABLE,
        table_name=b"FASHION_SUITE_ESSENCE",
    )
    entries = {
        fashion_id: _parse_fashion(fashion_id, row)
        for fashion_id, row in _rows(fashion_data, fashion_index)
    }
    suites: dict[int, dict[str, Any]] = {}
    relation_count = 0
    suite_item_count = 0
    for suite_id, row in _rows(suite_data, suite_index):
        suite = _parse_suite(suite_id, row)
        decoded_items: list[dict[str, int]] = []
        for item_type, encoded_item_id in suite["items"]:
            suite_item_count += 1
            # FashionSuite stores FashionItem identifiers as 2 * fashion_index.
            # The installed table currently contains only type-1, even IDs.
            fashion_id = (
                encoded_item_id // 2
                if item_type == 1 and encoded_item_id % 2 == 0
                else None
            )
            if fashion_id is None:
                continue
            entry = entries.get(fashion_id)
            if entry is None:
                continue
            decoded_items.append(
                {
                    "item_type": item_type,
                    "fashion_index": fashion_id,
                    "encoded_item_id": encoded_item_id,
                }
            )
            entry["suites"].append(
                {
                    "suite_id": suite_id,
                    "suite_name": suite["suite_name"],
                    "item_type": item_type,
                }
            )
            relation_count += 1
        encoded_main_fashion_id = suite["main_fashion_id"]
        main_fashion_id = (
            encoded_main_fashion_id // 2
            if encoded_main_fashion_id % 2 == 0
            and encoded_main_fashion_id // 2 in entries
            else None
        )
        suites[suite_id] = {
            "suite_id": suite_id,
            "suite_name": suite["suite_name"],
            "suite_type": suite["suite_type"],
            "quality": suite["quality"],
            "icon_id": suite["icon_id"],
            "main_fashion_id": main_fashion_id,
            "encoded_main_fashion_id": encoded_main_fashion_id,
            "items": decoded_items,
        }

    return FashionCatalog(
        entries=entries,
        suites=suites,
        metadata={
            "path": str(path.resolve()),
            "sha256": hashlib.sha256(raw).hexdigest().upper(),
            "package_bytes": len(raw),
            "fashion_table_version": EXPECTED_FASHION_TABLE[0],
            "fashion_catalog_count": len(entries),
            "suite_table_version": EXPECTED_FASHION_SUITE_TABLE[0],
            "suite_catalog_count": EXPECTED_FASHION_SUITE_TABLE[1],
            "suite_item_count": suite_item_count,
            "suite_relation_count": relation_count,
            "unmatched_suite_item_count": suite_item_count - relation_count,
            "parsed_package_end": suite_end,
        },
    )


# Compact-catalog build chain
ROOT = Path(__file__).resolve().parent
DATA_ROOT = ROOT / "DatAnDict"
SOURCE = DATA_ROOT / "YKAPoolCatalog.json"
OUT = DATA_ROOT / "YKACompactCatalog.json"
REGISTRY = DATA_ROOT / "YKACompactRegistry.json"
SCALE = 1_000_000
CATALOG_ID = "00000102"
DEFAULT_WIDTH = 261


def _round_half_up(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ValueError("coordinate denominator must be positive")
    return (numerator + denominator // 2) // denominator


def coordinate(center: list[int], source: list[int], width: int) -> list[int]:
    """Apply the integer-v1 coordinate rule."""
    if (
        len(center) != 2
        or len(source) != 2
        or any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in center + source
        )
        or not 120 <= width <= 1200
    ):
        raise ValueError("invalid coordinate input")
    center_x, center_y = center
    source_width, source_height = source
    if source_width <= 0 or source_height <= 0:
        raise ValueError("invalid source dimensions")
    marker_size = source_width // 20
    x = _round_half_up(
        2 * center_x * width - marker_size * SCALE,
        2 * SCALE,
    )
    y = _round_half_up(
        2 * center_y * source_height * width
        - marker_size * SCALE * source_width,
        2 * SCALE * source_width,
    )
    return [x, y]


def _decimal_center(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not a coordinate")
    decimal = value if isinstance(value, Decimal) else Decimal(value)
    if not decimal.is_finite() or not 0 <= decimal <= 1:
        raise ValueError("coordinate outside [0,1]")
    if decimal.as_tuple().exponent < -6:
        raise ValueError("coordinate has more than six decimal places")
    scaled = decimal * SCALE
    if scaled != scaled.to_integral_value():
        raise ValueError("coordinate is not integral at scale")
    return int(scaled)


def _ordinary_entry(pool: dict[str, Any]) -> dict[str, Any]:
    geometry = pool.get("image_geometry")
    if not isinstance(geometry, dict):
        raise ValueError(f"pool {pool.get('key', '')} has no geometry")
    source = [
        int(geometry.get("source_width") or 0),
        int(geometry.get("source_height") or 0),
    ]
    centers: list[list[int]] = []
    for pair in geometry.get("slot_centers", []):
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError(f"pool {pool.get('key', '')} has invalid center")
        centers.append([_decimal_center(pair[0]), _decimal_center(pair[1])])
    verified = pool.get("piece_mapping_confidence") == "verified_complete"
    verified_centers = centers if verified else []
    return {
        "key": pool["key"],
        "name": pool.get("name", ""),
        "n": len(verified_centers),
        "slots": [
            coordinate(center, source, DEFAULT_WIDTH)
            for center in verified_centers
        ],
        "source": source,
        "center_integer_pairs": verified_centers,
    }


def _content_hash(catalog: dict[str, Any]) -> str:
    canonical = dict(catalog)
    canonical["content_sha256"] = ""
    payload = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build() -> dict[str, Any]:
    source = json.loads(SOURCE.read_text(encoding="utf-8"), parse_float=Decimal)
    pools = source.get("pools")
    if not isinstance(pools, list):
        raise ValueError("pool catalog has no pools array")
    ordinary = [pool for pool in pools if pool.get("att_type") != "attbg"]
    background = [pool for pool in pools if pool.get("att_type") == "attbg"]
    if len(ordinary) != 203 or len(background) != 126:
        raise ValueError("unexpected compact catalog pool counts")
    catalog: dict[str, Any] = {
        "schema_version": 1,
        "catalog_id": CATALOG_ID,
        "scale": SCALE,
        "default_width": DEFAULT_WIDTH,
        "status_count": 11,
        "coordinate_rule_version": "integer-v1",
        "ordinary": [_ordinary_entry(pool) for pool in ordinary],
        "background": [
            {"key": pool["key"], "name": pool.get("name", "")}
            for pool in background
        ],
        "status_schema": {"count": 11, "values": list(range(11))},
        "coordinate_sha256": {},
        "content_sha256": "",
    }
    for width in (120, 261, 1200):
        flat_coordinates: list[int] = []
        for entry in catalog["ordinary"]:
            for center in entry["center_integer_pairs"]:
                flat_coordinates.extend(
                    coordinate(center, entry["source"], width)
                )
        serialized = json.dumps(
            flat_coordinates, separators=(",", ":")
        ).encode("ascii")
        catalog["coordinate_sha256"][str(width)] = hashlib.sha256(
            serialized
        ).hexdigest()
    catalog["content_sha256"] = _content_hash(catalog)
    return catalog


def main() -> None:
    if re.fullmatch(r"[0-9]{8}", CATALOG_ID) is None:
        raise RuntimeError("catalog_id must be exactly eight decimal digits")
    catalog = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if OUT.exists():
        previous = json.loads(OUT.read_text(encoding="utf-8"))
        if (
            previous.get("catalog_id") == CATALOG_ID
            and previous.get("content_sha256") != catalog["content_sha256"]
        ):
            raise RuntimeError("catalog content changed for immutable catalog_id")
    registry: dict[str, Any] = {"schema_version": 1, "catalogs": {}}
    if REGISTRY.exists():
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    catalogs = registry.setdefault("catalogs", {})
    previous_hash = catalogs.get(CATALOG_ID)
    if previous_hash is not None and previous_hash != catalog["content_sha256"]:
        raise RuntimeError("catalog_id already refers to different content")
    catalogs[CATALOG_ID] = catalog["content_sha256"]
    OUT.write_text(
        json.dumps(catalog, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    REGISTRY.write_text(
        json.dumps(registry, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
