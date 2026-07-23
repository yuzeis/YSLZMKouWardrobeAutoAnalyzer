"""C1 compact wire codec with draw-count extensions 2 and 3."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import re
import zlib
from dataclasses import dataclass
from math import comb, factorial
from pathlib import Path
from typing import Any, Iterable, Sequence


HEADER_DOMAIN = b"YSLZM-WIRE-H1"
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_WIRE_BYTES = 16 * 1024 * 1024
MIN_WIDTH = 120
MAX_WIDTH = 1200
SUPPORTED_CODECS = frozenset({0, 1, 2, 3})
BASE4096_START = 0x4E00
BASE4096_END = 0x5DFF
BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE45_INDEX = {character: index for index, character in enumerate(BASE45_ALPHABET)}
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_BASE64_CHARACTERS = 4 * ((MAX_WIRE_BYTES + 2) // 3)
MAX_BASE4096_CHARACTERS = ((MAX_WIRE_BYTES + 1) * 8 + 11) // 12
MAX_J1_CHARACTERS = 2 * MAX_JSON_BYTES + 64

QR_KIND_COMPRESSED_JSON = "压缩原始 JSON"
QR_KIND_C1_BASE64 = "C1 Base64"
QR_KIND_C1_BASE4096 = "C1 Base4096"


class CodecError(ValueError):
    """Raised for malformed catalogs, canonical JSON, or compact wire data."""


class TransportError(ValueError):
    """Raised when a textual transport is malformed or non-canonical."""


class ArtifactError(ValueError):
    """Raised when the import artifacts cannot be generated atomically."""


_BASE64_RE = re.compile(
    r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)
_J1_RE = re.compile(
    r"J1:(0|[1-9][0-9]*):([0-9A-F]{8}):([0-9A-Z $%*+\-./:]+)"
)


class _BitWriter:
    def __init__(self) -> None:
        self.bits: list[int] = []

    def write_bits(self, value: int, width: int) -> None:
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not isinstance(width, int)
            or width < 0
            or value < 0
            or (width == 0 and value != 0)
            or (width > 0 and value >= 1 << width)
        ):
            raise CodecError("位字段超出范围")
        self.bits.extend((value >> shift) & 1 for shift in range(width - 1, -1, -1))

    def to_bytes(self) -> bytes:
        bits = self.bits + [0] * ((-len(self.bits)) % 8)
        return bytes(
            sum(bits[offset + bit] << (7 - bit) for bit in range(8))
            for offset in range(0, len(bits), 8)
        )


class _BitReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    @property
    def total_bits(self) -> int:
        return len(self.data) * 8

    def read_bits(self, width: int) -> int:
        if not isinstance(width, int) or width < 0:
            raise CodecError("位字段宽度无效")
        if self.position + width > self.total_bits:
            raise CodecError("payload 提前耗尽")
        value = 0
        for _ in range(width):
            byte = self.data[self.position // 8]
            bit = (byte >> (7 - self.position % 8)) & 1
            value = (value << 1) | bit
            self.position += 1
        return value

    def require_zero_padding(self) -> None:
        remaining = self.total_bits - self.position
        if remaining >= 8:
            raise CodecError("payload 含多余数据")
        if self.read_bits(remaining) != 0:
            raise CodecError("payload 补位必须为 0")


def _write_truncated(writer: _BitWriter, value: int, count: int) -> None:
    if count <= 0 or not 0 <= value < count:
        raise CodecError("truncated binary 取值无效")
    if count == 1:
        return
    base_width = count.bit_length() - 1
    threshold = (1 << (base_width + 1)) - count
    if value < threshold:
        writer.write_bits(value, base_width)
    else:
        writer.write_bits(value + threshold, base_width + 1)


def _read_truncated(reader: _BitReader, count: int) -> int:
    if count <= 0:
        raise CodecError("truncated binary 范围无效")
    if count == 1:
        return 0
    base_width = count.bit_length() - 1
    threshold = (1 << (base_width + 1)) - count
    prefix = reader.read_bits(base_width)
    if prefix < threshold:
        return prefix
    return ((prefix << 1) | reader.read_bits(1)) - threshold


def _truncated_length(value: int, count: int) -> int:
    if count <= 0 or not 0 <= value < count:
        raise CodecError("truncated binary 取值无效")
    if count == 1:
        return 0
    base_width = count.bit_length() - 1
    threshold = (1 << (base_width + 1)) - count
    return base_width if value < threshold else base_width + 1


def _rank_combination(n: int, k: int, selected: Sequence[int]) -> int:
    if (
        not 0 <= k <= n
        or len(selected) != k
        or list(selected) != sorted(set(selected))
        or any(index < 0 or index >= n for index in selected)
    ):
        raise CodecError("组合索引无效")
    rank = 0
    previous = -1
    for position, current in enumerate(selected):
        for candidate in range(previous + 1, current):
            rank += comb(n - candidate - 1, k - position - 1)
        previous = current
    return rank


def _unrank_combination(n: int, k: int, rank: int) -> list[int]:
    count = comb(n, k) if 0 <= k <= n else 0
    if count <= 0 or not 0 <= rank < count:
        raise CodecError("组合排名越界")
    selected: list[int] = []
    previous = -1
    for position in range(k):
        for candidate in range(previous + 1, n):
            candidate_count = comb(n - candidate - 1, k - position - 1)
            if rank < candidate_count:
                selected.append(candidate)
                previous = candidate
                break
            rank -= candidate_count
        else:
            raise CodecError("组合排名无法还原")
    if rank != 0:
        raise CodecError("组合排名存在余数")
    return selected


def _rank_histogram(counts: Sequence[int], pool_count: int, status_count: int) -> int:
    if len(counts) != status_count or sum(counts) != pool_count or any(value < 0 for value in counts):
        raise CodecError("状态直方图无效")
    rank = 0
    remaining = pool_count
    for status in range(status_count - 1):
        for value in range(counts[status]):
            rank += comb(remaining - value + status_count - status - 2, status_count - status - 2)
        remaining -= counts[status]
    return rank


def _unrank_histogram(
    pool_count: int,
    status_count: int,
    rank: int,
) -> list[int]:
    total = comb(pool_count + status_count - 1, status_count - 1)
    if not 0 <= rank < total:
        raise CodecError("状态直方图排名越界")
    counts: list[int] = []
    remaining = pool_count
    for status in range(status_count - 1):
        for value in range(remaining + 1):
            block = comb(
                remaining - value + status_count - status - 2,
                status_count - status - 2,
            )
            if rank < block:
                counts.append(value)
                remaining -= value
                break
            rank -= block
        else:
            raise CodecError("状态直方图无法还原")
    counts.append(remaining)
    if rank != 0:
        raise CodecError("状态直方图排名存在余数")
    return counts


def _permutations(counts: Sequence[int]) -> int:
    total = sum(counts)
    value = factorial(total)
    for count in counts:
        value //= factorial(count)
    return value


def _rank_sequence(statuses: Sequence[int], counts: Sequence[int]) -> int:
    remaining = list(counts)
    rank = 0
    for status in statuses:
        if not 0 <= status < len(remaining) or remaining[status] <= 0:
            raise CodecError("状态序列与直方图不一致")
        for candidate in range(status):
            if remaining[candidate] > 0:
                remaining[candidate] -= 1
                rank += _permutations(remaining)
                remaining[candidate] += 1
        remaining[status] -= 1
    if any(remaining):
        raise CodecError("状态直方图未归零")
    return rank


def _unrank_sequence(counts: Sequence[int], rank: int) -> list[int]:
    total_sequences = _permutations(counts)
    if not 0 <= rank < total_sequences:
        raise CodecError("状态序列排名越界")
    remaining = list(counts)
    statuses: list[int] = []
    for _ in range(sum(counts)):
        for candidate, count in enumerate(remaining):
            if count == 0:
                continue
            remaining[candidate] -= 1
            block = _permutations(remaining)
            if rank < block:
                statuses.append(candidate)
                break
            rank -= block
            remaining[candidate] += 1
        else:
            raise CodecError("状态序列无法还原")
    if rank != 0 or any(remaining):
        raise CodecError("状态序列未完整消费")
    return statuses


def _write_gamma(writer: _BitWriter, value: int) -> None:
    if not 1 <= value <= MAX_SAFE_INTEGER:
        raise CodecError("抽数超出 JavaScript 安全整数范围")
    suffix_width = value.bit_length() - 1
    writer.write_bits(0, suffix_width)
    writer.write_bits(value, suffix_width + 1)


def _read_gamma(reader: _BitReader) -> int:
    zero_count = 0
    while reader.read_bits(1) == 0:
        zero_count += 1
        if zero_count > 52:
            raise CodecError("抽数 gamma 编码超出安全范围")
    suffix = reader.read_bits(zero_count)
    value = (1 << zero_count) | suffix
    if value > MAX_SAFE_INTEGER:
        raise CodecError("抽数超出 JavaScript 安全整数范围")
    return value


def _write_subset(writer: _BitWriter, n: int, selected: Sequence[int]) -> None:
    k = len(selected)
    _rank_combination(n, k, selected)
    if n <= 0:
        if k:
            raise CodecError("无槽位卡池不能包含坐标")
        return
    if k == 0:
        writer.write_bits(0, 2)
        return
    if k == n:
        writer.write_bits(1, 2)
        return
    writer.write_bits(1, 1)
    combination_rank = _rank_combination(n, k, selected)
    combination_count = comb(n, k)
    combination_length = _truncated_length(k - 1, n - 1) + _truncated_length(
        combination_rank,
        combination_count,
    )
    if combination_length <= n:
        writer.write_bits(0, 1)
        _write_truncated(writer, k - 1, n - 1)
        _write_truncated(writer, combination_rank, combination_count)
        return
    writer.write_bits(1, 1)
    bitmap = 0
    for index in selected:
        bitmap |= 1 << (n - index - 1)
    writer.write_bits(bitmap, n)


def _read_subset(reader: _BitReader, n: int) -> list[int]:
    if n <= 0:
        return []
    first = reader.read_bits(1)
    if first == 0:
        return [] if reader.read_bits(1) == 0 else list(range(n))
    representation = reader.read_bits(1)
    if representation == 0:
        k = _read_truncated(reader, n - 1) + 1
        rank = _read_truncated(reader, comb(n, k))
        return _unrank_combination(n, k, rank)
    bitmap = reader.read_bits(n)
    selected = [index for index in range(n) if bitmap & (1 << (n - index - 1))]
    if not selected or len(selected) == n:
        raise CodecError("RAW 位图不能表示 NONE 或 ALL")
    return selected


def _content_hash(catalog: dict[str, Any]) -> str:
    canonical = dict(catalog)
    canonical["content_sha256"] = ""
    payload = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class _Catalog:
    source: dict[str, Any]
    catalog_id: str
    default_width: int
    status_count: int
    scale: int
    ordinary: tuple[dict[str, Any], ...]
    background: tuple[dict[str, Any], ...]


def _catalog(catalog: dict[str, Any]) -> _Catalog:
    if not isinstance(catalog, dict):
        raise CodecError("紧凑目录根节点必须是对象")
    catalog_id = catalog.get("catalog_id")
    if not isinstance(catalog_id, str) or re.fullmatch(r"[0-9]{8}", catalog_id) is None:
        raise CodecError("catalog_id 必须是 8 位十进制字符串")
    default_width = catalog.get("default_width")
    status_count = catalog.get("status_count")
    scale = catalog.get("scale")
    if (
        not isinstance(default_width, int)
        or isinstance(default_width, bool)
        or not MIN_WIDTH <= default_width <= MAX_WIDTH
        or not isinstance(status_count, int)
        or isinstance(status_count, bool)
        or status_count <= 0
        or not isinstance(scale, int)
        or isinstance(scale, bool)
        or scale <= 0
    ):
        raise CodecError("紧凑目录参数无效")
    ordinary_value = catalog.get("ordinary")
    background_value = catalog.get("background")
    if not isinstance(ordinary_value, list) or not isinstance(background_value, list):
        raise CodecError("紧凑目录缺少卡池列表")
    ordinary = tuple(ordinary_value)
    background = tuple(background_value)
    keys: list[str] = []
    for pool in ordinary:
        if not isinstance(pool, dict) or not isinstance(pool.get("key"), str) or not pool["key"]:
            raise CodecError("普通卡池目录项无效")
        n = pool.get("n")
        centers = pool.get("center_integer_pairs")
        source = pool.get("source")
        if (
            not isinstance(n, int)
            or isinstance(n, bool)
            or n < 0
            or not isinstance(centers, list)
            or len(centers) != n
            or not isinstance(source, list)
            or len(source) != 2
            or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in source)
            or (n > 0 and any(value <= 0 for value in source))
        ):
            raise CodecError(f"卡池 {pool.get('key', '')} 的槽位目录无效")
        for center in centers:
            if (
                not isinstance(center, list)
                or len(center) != 2
                or any(
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or not 0 <= value <= scale
                    for value in center
                )
            ):
                raise CodecError(f"卡池 {pool['key']} 的整数中心无效")
        keys.append(pool["key"])
    for pool in background:
        if not isinstance(pool, dict) or not isinstance(pool.get("key"), str) or not pool["key"]:
            raise CodecError("背景目录项无效")
        keys.append(pool["key"])
    if len(keys) != len(set(keys)):
        raise CodecError("紧凑目录包含重复 key")
    expected_hash = catalog.get("content_sha256")
    if (
        not isinstance(expected_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
        or _content_hash(catalog) != expected_hash
    ):
        raise CodecError("紧凑目录 content_sha256 缺失或不匹配")
    return _Catalog(
        source=catalog,
        catalog_id=catalog_id,
        default_width=default_width,
        status_count=status_count,
        scale=scale,
        ordinary=ordinary,
        background=background,
    )


def load_catalog(
    path: Path | dict[str, Any],
    registry_path: Path | dict[str, Any] | None = None,
) -> dict[str, Any]:
    if isinstance(path, dict):
        catalog = copy.deepcopy(path)
    else:
        try:
            catalog = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise CodecError(f"无法读取紧凑目录：{error}") from error
    view = _catalog(catalog)
    if registry_path is not None:
        if isinstance(registry_path, dict):
            registry = copy.deepcopy(registry_path)
        else:
            try:
                registry = json.loads(registry_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise CodecError(f"无法读取紧凑目录注册表：{error}") from error
        catalogs = registry.get("catalogs")
        if not isinstance(catalogs, dict):
            raise CodecError("紧凑目录注册表结构无效")
        registered = catalogs.get(view.catalog_id)
        if registered != catalog.get("content_sha256"):
            raise CodecError("紧凑目录未在注册表中登记或哈希不匹配")
    return catalog


def _slot_points(pool: dict[str, Any], width: int, scale: int) -> list[tuple[int, int]]:
    source_width, source_height = pool["source"]
    marker_size = source_width // 20
    points: list[tuple[int, int]] = []
    for center_x, center_y in pool["center_integer_pairs"]:
        x = (
            2 * center_x * width - marker_size * scale + scale
        ) // (2 * scale)
        y = (
            2 * center_y * source_height * width
            - marker_size * scale * source_width
            + scale * source_width
        ) // (2 * scale * source_width)
        points.append((x, y))
    if len(points) != pool["n"] or len(points) != len(set(points)):
        raise CodecError(f"卡池 {pool['key']} 的槽位坐标不唯一")
    return points


def _parse_json_rows(
    code: str | list[Any],
    catalog: _Catalog,
    width: int,
) -> tuple[list[int], list[int], list[list[int]], list[int] | None, str]:
    if isinstance(code, str):
        if len(code.encode("utf-8")) > MAX_WIRE_BYTES:
            raise CodecError("原始导入 JSON 超过安全上限")
        try:
            rows = json.loads(code, parse_constant=lambda value: (_ for _ in ()).throw(CodecError(value)))
        except (json.JSONDecodeError, CodecError) as error:
            raise CodecError("原始导入 JSON 无效") from error
        canonical_input = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
        if canonical_input != code:
            raise CodecError("原始导入 JSON 不是规范单行格式")
    else:
        rows = code
        canonical_input = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    if not isinstance(rows, list):
        raise CodecError("原始导入 JSON 根节点必须是数组")

    ordinary_count = len(catalog.ordinary)
    background_count = len(catalog.background)
    if len(rows) not in {ordinary_count, ordinary_count + background_count}:
        raise CodecError("原始导入 JSON 必须包含全部普通池及可选的全部背景")
    has_background = (
        background_count > 0
        and len(rows) == ordinary_count + background_count
    )

    statuses: list[int] = []
    draw_counts: list[int] = []
    selected_by_pool: list[list[int]] = []
    for index, pool in enumerate(catalog.ordinary):
        row = rows[index]
        if not isinstance(row, list) or len(row) not in {3, 5} or row[0] != pool["key"]:
            raise CodecError(f"普通卡池顺序或结构无效：{pool['key']}")
        draw_count = row[1]
        status = row[2]
        if (
            not isinstance(draw_count, int)
            or isinstance(draw_count, bool)
            or not 0 <= draw_count <= MAX_SAFE_INTEGER
        ):
            raise CodecError(f"卡池 {pool['key']} 的抽数无效")
        if (
            not isinstance(status, int)
            or isinstance(status, bool)
            or not 0 <= status < catalog.status_count
        ):
            raise CodecError(f"卡池 {pool['key']} 的状态无效")
        draw_counts.append(draw_count)
        statuses.append(status)

        if len(row) == 3:
            selected_by_pool.append([])
            continue
        if row[3] != "" or not isinstance(row[4], list) or not row[4] or len(row[4]) % 2:
            raise CodecError(f"卡池 {pool['key']} 的坐标结构无效")
        if any(not isinstance(value, int) or isinstance(value, bool) for value in row[4]):
            raise CodecError(f"卡池 {pool['key']} 的坐标必须是整数")
        coordinates = [tuple(row[4][offset : offset + 2]) for offset in range(0, len(row[4]), 2)]
        points = _slot_points(pool, width, catalog.scale)
        point_to_index = {point: slot for slot, point in enumerate(points)}
        try:
            selected = [point_to_index[point] for point in coordinates]
        except KeyError as error:
            raise CodecError(f"卡池 {pool['key']} 包含未知坐标") from error
        if selected != sorted(set(selected)):
            raise CodecError(f"卡池 {pool['key']} 的坐标顺序或重复项无效")
        selected_by_pool.append(selected)

    background_values: list[int] | None = None
    if has_background:
        background_values = []
        for offset, background in enumerate(catalog.background, start=ordinary_count):
            row = rows[offset]
            if (
                not isinstance(row, list)
                or len(row) != 2
                or row[0] != background["key"]
                or not isinstance(row[1], int)
                or isinstance(row[1], bool)
                or row[1] not in {0, 1}
            ):
                raise CodecError(f"背景顺序或结构无效：{background['key']}")
            background_values.append(row[1])
    return statuses, draw_counts, selected_by_pool, background_values, canonical_input


def _catalog_id_bytes(catalog_id: str) -> bytes:
    return bytes(
        (int(catalog_id[offset]) << 4) | int(catalog_id[offset + 1])
        for offset in range(0, 8, 2)
    )


def _decode_catalog_id(data: bytes) -> str:
    digits: list[str] = []
    for byte in data:
        high, low = byte >> 4, byte & 0x0F
        if high > 9 or low > 9:
            raise CodecError("catalog_id 包含非法 BCD nibble")
        digits.extend((str(high), str(low)))
    return "".join(digits)


def encode(
    code: str | list[Any],
    catalog: dict[str, Any],
    *,
    target_width: int | None = None,
) -> bytes:
    """Encode canonical JSON as a canonical H1 wire."""
    view = _catalog(catalog)
    width = view.default_width if target_width is None else target_width
    if (
        not isinstance(width, int)
        or isinstance(width, bool)
        or not MIN_WIDTH <= width <= MAX_WIDTH
    ):
        raise CodecError("详情图宽度必须是 120 到 1200 的整数")
    statuses, draws, subsets, backgrounds, _ = _parse_json_rows(code, view, width)
    has_draws = any(draws)
    has_backgrounds = backgrounds is not None
    codec_id = (
        3 if has_draws and has_backgrounds else
        2 if has_draws else
        1 if has_backgrounds else
        0
    )

    writer = _BitWriter()
    if width == view.default_width:
        writer.write_bits(0, 1)
    else:
        writer.write_bits(1, 1)
        writer.write_bits(width - MIN_WIDTH, 11)

    histogram = [statuses.count(status) for status in range(view.status_count)]
    histogram_count = comb(len(view.ordinary) + view.status_count - 1, view.status_count - 1)
    _write_truncated(
        writer,
        _rank_histogram(histogram, len(view.ordinary), view.status_count),
        histogram_count,
    )
    sequence_count = _permutations(histogram)
    _write_truncated(writer, _rank_sequence(statuses, histogram), sequence_count)

    for pool, selected in zip(view.ordinary, subsets):
        _write_subset(writer, pool["n"], selected)

    if has_draws:
        nonzero = [index for index, value in enumerate(draws) if value > 0]
        _write_truncated(writer, len(nonzero), len(view.ordinary) + 1)
        _write_truncated(
            writer,
            _rank_combination(len(view.ordinary), len(nonzero), nonzero),
            comb(len(view.ordinary), len(nonzero)),
        )
        for index in nonzero:
            _write_gamma(writer, draws[index])

    if backgrounds is not None:
        for value in backgrounds:
            writer.write_bits(value, 1)

    payload = writer.to_bytes()
    prefix = _catalog_id_bytes(view.catalog_id) + bytes((codec_id,))
    checksum = zlib.crc32(HEADER_DOMAIN + prefix + payload) & 0xFFFFFFFF
    return prefix + checksum.to_bytes(4, "big") + payload


def decode(wire: bytes | bytearray | memoryview, catalog: dict[str, Any]) -> str:
    """Decode a canonical H1 wire and return canonical JSON."""
    if not isinstance(wire, (bytes, bytearray, memoryview)):
        raise TypeError("wire 必须是字节序列")
    raw = bytes(wire)
    if len(raw) < 9:
        raise CodecError("wire 长度小于 9 字节")
    if len(raw) > MAX_WIRE_BYTES:
        raise CodecError("wire 超过安全上限")
    catalog_id = _decode_catalog_id(raw[:4])
    codec_id = raw[4]
    if codec_id not in SUPPORTED_CODECS:
        raise CodecError("未知 codec_id")
    payload = raw[9:]
    expected_crc = int.from_bytes(raw[5:9], "big")
    actual_crc = zlib.crc32(HEADER_DOMAIN + raw[:5] + payload) & 0xFFFFFFFF
    if expected_crc != actual_crc:
        raise CodecError("wire CRC32 校验失败")

    view = _catalog(catalog)
    if catalog_id != view.catalog_id:
        raise CodecError("wire catalog_id 与本地目录不匹配")
    has_draws = codec_id in {2, 3}
    has_backgrounds = codec_id in {1, 3}
    if has_backgrounds and not view.background:
        raise CodecError("codec 声明背景段，但目录没有背景")

    reader = _BitReader(payload)
    override = reader.read_bits(1)
    width = view.default_width
    if override:
        offset = reader.read_bits(11)
        if offset > MAX_WIDTH - MIN_WIDTH:
            raise CodecError("width_offset 越界")
        width = MIN_WIDTH + offset
        if width == view.default_width:
            raise CodecError("默认宽度禁止使用 override 表示")

    histogram_count = comb(len(view.ordinary) + view.status_count - 1, view.status_count - 1)
    histogram_rank = _read_truncated(reader, histogram_count)
    histogram = _unrank_histogram(len(view.ordinary), view.status_count, histogram_rank)
    sequence_count = _permutations(histogram)
    sequence_rank = _read_truncated(reader, sequence_count)
    statuses = _unrank_sequence(histogram, sequence_rank)

    subsets = [_read_subset(reader, pool["n"]) for pool in view.ordinary]
    draws = [0] * len(view.ordinary)
    if has_draws:
        nonzero_count = _read_truncated(reader, len(view.ordinary) + 1)
        nonzero_rank = _read_truncated(reader, comb(len(view.ordinary), nonzero_count))
        nonzero = _unrank_combination(
            len(view.ordinary),
            nonzero_count,
            nonzero_rank,
        )
        for index in nonzero:
            draws[index] = _read_gamma(reader)

    background_values: list[int] | None = None
    if has_backgrounds:
        background_values = [reader.read_bits(1) for _ in view.background]
    reader.require_zero_padding()

    rows: list[list[Any]] = []
    for index, pool in enumerate(view.ordinary):
        points = _slot_points(pool, width, view.scale)
        coordinates = [value for slot in subsets[index] for value in points[slot]]
        row: list[Any] = [pool["key"], draws[index], statuses[index]]
        if coordinates:
            row.extend(("", coordinates))
        rows.append(row)
    if background_values is not None:
        rows.extend(
            [background["key"], value]
            for background, value in zip(view.background, background_values)
        )
    code = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    if encode(code, catalog, target_width=width) != raw:
        raise CodecError("wire 不是规范编码")
    return code


def wire_codec_id(wire: bytes | bytearray | memoryview) -> int:
    raw = bytes(wire)
    if len(raw) < 9:
        raise CodecError("wire 长度小于 9 字节")
    return raw[4]


encode_compact = encode
decode_compact = decode


def _bytes(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("传输输入必须是字节序列")
    return bytes(value)


def encode_base64(data: bytes | bytearray | memoryview) -> str:
    """Encode bytes as canonical padded RFC 4648 Base64."""
    raw = _bytes(data)
    if len(raw) > MAX_WIRE_BYTES:
        raise TransportError("C1 wire 超过安全上限")
    return base64.b64encode(raw).decode("ascii")


def decode_base64(text: str) -> bytes:
    """Decode strict padded RFC 4648 Base64."""
    if (
        not isinstance(text, str)
        or len(text) > MAX_BASE64_CHARACTERS
        or _BASE64_RE.fullmatch(text) is None
    ):
        raise TransportError("C1 Base64 格式无效")
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise TransportError("C1 Base64 格式无效") from error
    if encode_base64(decoded) != text:
        raise TransportError("C1 Base64 不是规范编码")
    return decoded


def encode_base4096(data: bytes | bytearray | memoryview) -> str:
    """Encode wire bytes using Base4096-Han-v1 and its 0x80 sentinel."""
    source = _bytes(data)
    if len(source) > MAX_WIRE_BYTES:
        raise TransportError("C1 wire 超过安全上限")
    raw = source + b"\x80"
    bits = "".join(f"{byte:08b}" for byte in raw)
    bits += "0" * ((-len(bits)) % 12)
    return "".join(
        chr(BASE4096_START + int(bits[offset : offset + 12], 2))
        for offset in range(0, len(bits), 12)
    )


def decode_base4096(text: str) -> bytes:
    """Decode strict Base4096-Han-v1 with unique length recovery."""
    if (
        not isinstance(text, str)
        or not text
        or len(text) > MAX_BASE4096_CHARACTERS
    ):
        raise TransportError("C1 Base4096 格式无效")
    values: list[int] = []
    for character in text:
        value = ord(character) - BASE4096_START
        if not 0 <= value < 4096:
            raise TransportError("C1 Base4096 包含字表外字符")
        values.append(value)

    bits = "".join(f"{value:012b}" for value in values)
    total_bits = len(bits)
    minimum_bytes = max(1, (total_bits - 11 + 7) // 8)
    maximum_bytes = total_bits // 8
    candidates: list[bytes] = []
    for byte_length in range(minimum_bytes, maximum_bytes + 1):
        pad_length = total_bits - byte_length * 8
        if not 0 <= pad_length <= 11:
            continue
        if any(bit != "0" for bit in bits[byte_length * 8 :]):
            continue
        raw = bytes(
            int(bits[offset : offset + 8], 2)
            for offset in range(0, byte_length * 8, 8)
        )
        if raw and raw[-1] == 0x80:
            candidate = raw[:-1]
            if encode_base4096(candidate) == text:
                candidates.append(candidate)
    if len(candidates) != 1:
        raise TransportError("C1 Base4096 结束哨兵或长度不唯一")
    return candidates[0]


def base45_encode(data: bytes | bytearray | memoryview) -> str:
    """Encode bytes using the RFC 9285 Base45 alphabet."""
    raw = _bytes(data)
    output: list[str] = []
    for offset in range(0, len(raw), 2):
        if offset + 1 == len(raw):
            value = raw[offset]
            output.append(BASE45_ALPHABET[value % 45])
            output.append(BASE45_ALPHABET[value // 45])
            continue
        value = raw[offset] * 256 + raw[offset + 1]
        output.append(BASE45_ALPHABET[value % 45])
        output.append(BASE45_ALPHABET[(value // 45) % 45])
        output.append(BASE45_ALPHABET[value // (45 * 45)])
    return "".join(output)


def base45_decode(text: str) -> bytes:
    """Decode canonical Base45 text."""
    if not isinstance(text, str) or not text or len(text) % 3 == 1:
        raise TransportError("Base45 格式无效")
    try:
        values = [BASE45_INDEX[character] for character in text]
    except KeyError as error:
        raise TransportError("Base45 包含字表外字符") from error

    output = bytearray()
    offset = 0
    while offset < len(values):
        remaining = len(values) - offset
        group_length = 2 if remaining == 2 else 3
        value = values[offset] + values[offset + 1] * 45
        if group_length == 3:
            value += values[offset + 2] * 45 * 45
            if value > 0xFFFF:
                raise TransportError("Base45 三字符组越界")
            output.extend((value >> 8, value & 0xFF))
        else:
            if value > 0xFF:
                raise TransportError("Base45 双字符组越界")
            output.append(value)
        offset += group_length
    decoded = bytes(output)
    if base45_encode(decoded) != text:
        raise TransportError("Base45 不是规范编码")
    return decoded


def _reject_json_constant(value: str) -> None:
    raise TransportError(f"JSON 包含非有限数值：{value}")


def canonical_json(value: Any) -> str:
    """Serialize the import array using its compact canonical representation."""
    if not isinstance(value, list):
        raise TransportError("原始 JSON 根节点必须是数组")
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise TransportError("原始 JSON 无法规范序列化") from error


def canonicalize_json_text(text: str, *, require_canonical: bool = True) -> str:
    if not isinstance(text, str):
        raise TypeError("原始 JSON 必须是文本")
    if len(text) > MAX_JSON_BYTES:
        raise TransportError("原始 JSON 超过 J1 安全上限")
    try:
        value = json.loads(text, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, TransportError) as error:
        raise TransportError("原始 JSON 格式无效") from error
    canonical = canonical_json(value)
    if require_canonical and canonical != text:
        raise TransportError("原始 JSON 不是规范单行格式")
    return canonical


def encode_j1(value: str | list[Any]) -> str:
    """Compress canonical import JSON into the textual J1 envelope."""
    text = canonicalize_json_text(value) if isinstance(value, str) else canonical_json(value)
    raw = text.encode("utf-8")
    if len(raw) > MAX_JSON_BYTES:
        raise TransportError("原始 JSON 超过 J1 安全上限")
    compressor = zlib.compressobj(level=9, wbits=-15)
    compressed = compressor.compress(raw) + compressor.flush()
    checksum = zlib.crc32(raw) & 0xFFFFFFFF
    return f"J1:{len(raw)}:{checksum:08X}:{base45_encode(compressed)}"


def decode_j1(code: str) -> str:
    """Decode J1 and return the exact canonical JSON text."""
    if not isinstance(code, str):
        raise TypeError("J1 必须是文本")
    if len(code) > MAX_J1_CHARACTERS:
        raise TransportError("J1 文本超过安全上限")
    match = _J1_RE.fullmatch(code)
    if match is None:
        raise TransportError("J1 格式无效")
    expected_length = int(match.group(1))
    if expected_length > MAX_JSON_BYTES:
        raise TransportError("J1 声明长度超过安全上限")
    expected_crc = match.group(2)
    compressed = base45_decode(match.group(3))
    try:
        decompressor = zlib.decompressobj(wbits=-15)
        raw = decompressor.decompress(compressed, expected_length + 1)
        if len(raw) > expected_length or decompressor.unconsumed_tail:
            raise TransportError("J1 解压长度超过声明值")
        raw += decompressor.flush()
    except zlib.error as error:
        raise TransportError("J1 DEFLATE 正文无效") from error
    if not decompressor.eof or decompressor.unused_data:
        raise TransportError("J1 DEFLATE 正文被截断或含尾随数据")
    if len(raw) != expected_length:
        raise TransportError("J1 原始长度校验失败")
    if f"{zlib.crc32(raw) & 0xFFFFFFFF:08X}" != expected_crc:
        raise TransportError("J1 CRC32 校验失败")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TransportError("J1 正文不是 UTF-8") from error
    canonicalize_json_text(text)
    if encode_j1(text) != code:
        raise TransportError("J1 不是规范编码")
    return text


def decode_j1_object(code: str) -> list[Any]:
    return json.loads(decode_j1(code))


@dataclass(frozen=True)
class ImportArtifacts:
    raw_json: str
    compressed_json: str
    c1_base64: str
    c1_base4096: str
    wire: bytes
    catalog_id: str
    codec_id: int
    target_width: int

    def qr_payload(self, kind: str) -> str:
        values = {
            QR_KIND_COMPRESSED_JSON: self.compressed_json,
            QR_KIND_C1_BASE64: self.c1_base64,
            QR_KIND_C1_BASE4096: self.c1_base4096,
        }
        try:
            return values[kind]
        except KeyError as error:
            raise ArtifactError("二维码不提供原始 JSON 选项") from error


def _validate_expected_pool_keys(
    catalog: dict[str, Any],
    expected_pool_keys: Sequence[str] | None,
) -> None:
    if expected_pool_keys is None:
        return
    source_order = tuple(expected_pool_keys)
    if any(not isinstance(key, str) or not key for key in source_order):
        raise ArtifactError("卡池目录键序包含无效 key")
    compact_order = tuple(
        str(pool["key"])
        for pool in (*catalog["ordinary"], *catalog["background"])
    )
    if source_order == compact_order:
        return
    mismatch = next(
        (
            index
            for index, (source_key, compact_key) in enumerate(
                zip(source_order, compact_order)
            )
            if source_key != compact_key
        ),
        min(len(source_order), len(compact_order)),
    )
    source_key = (
        source_order[mismatch] if mismatch < len(source_order) else "<结束>"
    )
    compact_key = (
        compact_order[mismatch] if mismatch < len(compact_order) else "<结束>"
    )
    raise ArtifactError(
        "卡池目录与紧凑目录键序不一致："
        f"第 {mismatch + 1} 项为 {source_key!r} / {compact_key!r}"
    )


def build_import_artifacts(
    raw_json: str,
    *,
    catalog_path: Path | dict[str, Any],
    registry_path: Path | dict[str, Any],
    target_width: int,
    expected_pool_keys: Sequence[str] | None = None,
) -> ImportArtifacts:
    """Build and self-verify raw, J1, T1, and T2 representations."""
    try:
        catalog = load_catalog(catalog_path, registry_path)
        _validate_expected_pool_keys(catalog, expected_pool_keys)
        compressed = encode_j1(raw_json)
        if decode_j1(compressed) != raw_json:
            raise ArtifactError("J1 往返校验不一致")

        wire = encode(raw_json, catalog, target_width=target_width)
        if decode(wire, catalog) != raw_json:
            raise ArtifactError("C1 wire 往返校验不一致")

        base64_text = encode_base64(wire)
        if decode_base64(base64_text) != wire:
            raise ArtifactError("C1 Base64 往返校验不一致")
        base4096_text = encode_base4096(wire)
        if decode_base4096(base4096_text) != wire:
            raise ArtifactError("C1 Base4096 往返校验不一致")
    except (CodecError, TransportError, OSError, ValueError) as error:
        if isinstance(error, ArtifactError):
            raise
        raise ArtifactError(str(error)) from error

    return ImportArtifacts(
        raw_json=raw_json,
        compressed_json=compressed,
        c1_base64=base64_text,
        c1_base4096=base4096_text,
        wire=wire,
        catalog_id=str(catalog["catalog_id"]),
        codec_id=wire_codec_id(wire),
        target_width=target_width,
    )


b64_encode = encode_base64
b64_decode = decode_base64
compress_json = encode_j1
decompress_json = decode_j1
encode_c1_base64 = encode_base64
decode_c1_base64 = decode_base64
encode_c1_base4096 = encode_base4096
decode_c1_base4096 = decode_base4096
encode_compressed_json = encode_j1
decode_compressed_json = decode_j1
