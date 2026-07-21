"""QR rendering for the three supported compact import transports."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import zlib

import qrcode
from qrcode import util as qrcode_util
from qrcode.constants import (
    ERROR_CORRECT_H,
    ERROR_CORRECT_L,
    ERROR_CORRECT_M,
    ERROR_CORRECT_Q,
)
from qrcode.exceptions import DataOverflowError

import YKACompactCodec as transport
from YKACompactCodec import (
    QR_KIND_C1_BASE4096,
    QR_KIND_C1_BASE64,
    QR_KIND_COMPRESSED_JSON,
)
QR_KINDS = (
    QR_KIND_COMPRESSED_JSON,
    QR_KIND_C1_BASE64,
    QR_KIND_C1_BASE4096,
)
PREFERRED_MAX_VERSION = 20


class QRCapacityError(ValueError):
    """Raised when a valid transport cannot fit in a version-40 QR code."""


_ECC_LEVELS = (
    ("H", ERROR_CORRECT_H),
    ("Q", ERROR_CORRECT_Q),
    ("M", ERROR_CORRECT_M),
    ("L", ERROR_CORRECT_L),
)


def _validate_c1_wire(wire: bytes) -> None:
    if len(wire) < 9:
        raise ValueError("二维码数据不是完整 C1 wire")
    if any((byte >> 4) > 9 or (byte & 0x0F) > 9 for byte in wire[:4]):
        raise ValueError("二维码 C1 catalog_id 不是有效 BCD")
    if wire[4] not in {0, 1, 2, 3}:
        raise ValueError("二维码 C1 codec_id 不受支持")
    checksum = int.from_bytes(wire[5:9], "big")
    actual = zlib.crc32(b"YSLZM-WIRE-H1" + wire[:5] + wire[9:]) & 0xFFFFFFFF
    if checksum != actual:
        raise ValueError("二维码 C1 wire CRC32 校验失败")


@dataclass(frozen=True)
class QRMetadata:
    kind: str
    version: int
    error_correction: str
    pixels: int
    modules: int
    box_size: int
    border: int
    characters: int
    utf8_bytes: int
    high_density: bool

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def _validate_payload(kind: str, payload: str) -> None:
    if kind not in QR_KINDS:
        raise ValueError("二维码类型不受支持")
    if not isinstance(payload, str) or not payload:
        raise ValueError("二维码数据必须是非空文本")
    if payload.startswith("[") or payload.startswith("{"):
        raise ValueError("二维码不提供原始 JSON 选项")
    if kind == QR_KIND_COMPRESSED_JSON:
        transport.decode_j1(payload)
    elif kind == QR_KIND_C1_BASE64:
        _validate_c1_wire(transport.decode_base64(payload))
    else:
        _validate_c1_wire(transport.decode_base4096(payload))


def export_qr(
    kind: str,
    payload: str,
    *,
    box_size: int = 8,
    border: int = 4,
):
    """Render a scan-friendly QR, preferring stronger ECC through version 20."""
    _validate_payload(kind, payload)
    if not isinstance(box_size, int) or isinstance(box_size, bool) or box_size < 1:
        raise ValueError("二维码模块像素必须是正整数")
    if not isinstance(border, int) or isinstance(border, bool) or border < 4:
        raise ValueError("二维码静区至少为 4 个模块")

    last_capacity_error: Exception | None = None
    candidates: list[tuple[str, int, qrcode.QRCode]] = []
    for level_name, level_value in _ECC_LEVELS:
        qr = qrcode.QRCode(
            version=None,
            error_correction=level_value,
            box_size=box_size,
            border=border,
        )
        qr.add_data(payload)
        try:
            qr.make(fit=True)
        except DataOverflowError as error:
            last_capacity_error = error
            continue
        except ValueError:
            try:
                qrcode_util.create_data(40, level_value, qr.data_list)
            except DataOverflowError as error:
                last_capacity_error = error
                continue
            raise
        candidates.append((level_name, int(qr.version), qr))
    if not candidates:
        raise QRCapacityError(
            "二维码容量不足，无法在版本 40 内容纳该数据"
        ) from last_capacity_error

    preferred = [
        candidate for candidate in candidates
        if candidate[1] <= PREFERRED_MAX_VERSION
    ]
    level_name, version, qr = (
        preferred[0]
        if preferred
        else min(candidates, key=lambda item: item[1])
    )
    image = qr.make_image(fill_color="black", back_color="white")
    pixels = int(image.size[0])
    metadata = QRMetadata(
        kind=kind,
        version=version,
        error_correction=level_name,
        pixels=pixels,
        modules=17 + 4 * version,
        box_size=box_size,
        border=border,
        characters=len(payload),
        utf8_bytes=len(payload.encode("utf-8")),
        high_density=version > PREFERRED_MAX_VERSION,
    )
    return image, metadata


qr_export = export_qr
generate_qr = export_qr
