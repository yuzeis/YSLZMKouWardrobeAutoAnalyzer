from __future__ import annotations

import json
from pathlib import Path
import zlib

import pytest

import YKACompactCodec as codec
import YKAQR
from YKACompactCodec import encode_base4096, encode_base64, encode_j1
from YKAQR import (
    QR_KINDS,
    QR_KIND_C1_BASE4096,
    QR_KIND_C1_BASE64,
    QR_KIND_COMPRESSED_JSON,
    QRCapacityError,
    QRMetadata,
    export_qr,
)


def _wire() -> bytes:
    prefix = bytes.fromhex("12345678") + b"\x00"
    payload = b"\x00"
    crc = zlib.crc32(b"YSLZM-WIRE-H1" + prefix + payload) & 0xFFFFFFFF
    return prefix + crc.to_bytes(4, "big") + payload


def test_qr_renders_exactly_three_supported_kinds() -> None:
    payloads = {
        QR_KIND_COMPRESSED_JSON: encode_j1('[["a",0,0]]'),
        QR_KIND_C1_BASE64: encode_base64(_wire()),
        QR_KIND_C1_BASE4096: encode_base4096(_wire()),
    }
    assert tuple(payloads) == QR_KINDS
    for kind, payload in payloads.items():
        image, metadata = export_qr(kind, payload)
        assert image.mode in {"1", "L"}
        assert isinstance(metadata, QRMetadata)
        assert metadata.kind == kind
        assert metadata.error_correction in {"H", "Q", "M", "L"}
        assert metadata.pixels == image.size[0] == image.size[1]
        assert metadata.border == 4
        assert isinstance(metadata.high_density, bool)


def test_qr_rejects_raw_json_unknown_kind_and_small_quiet_zone() -> None:
    with pytest.raises(ValueError, match="原始 JSON"):
        export_qr(QR_KIND_COMPRESSED_JSON, '[["a",0,0]]')
    with pytest.raises(ValueError, match="不受支持"):
        export_qr("原始 JSON", encode_j1('[["a",0,0]]'))
    with pytest.raises(ValueError, match="静区"):
        export_qr(QR_KIND_C1_BASE64, encode_base64(_wire()), border=3)
    with pytest.raises(ValueError, match="完整 C1 wire"):
        export_qr(QR_KIND_C1_BASE64, encode_base64(b"wire"))


def test_qr_capacity_failure_has_a_stable_exception_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AlwaysOverflow:
        version = None

        def __init__(self, **_kwargs: object) -> None:
            pass

        def add_data(self, _payload: str) -> None:
            pass

        def make(self, *, fit: bool) -> None:
            assert fit is True
            raise YKAQR.DataOverflowError()

    monkeypatch.setattr(YKAQR.qrcode, "QRCode", AlwaysOverflow)

    with pytest.raises(QRCapacityError, match="容量不足"):
        export_qr(QR_KIND_COMPRESSED_JSON, encode_j1('[["a",0,0]]'))


def test_qr_does_not_relabel_unrelated_value_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenQRCode:
        data_list: list[object] = []
        version = None

        def __init__(self, **_kwargs: object) -> None:
            pass

        def add_data(self, _payload: str) -> None:
            pass

        def make(self, *, fit: bool) -> None:
            assert fit is True
            raise ValueError("unrelated QR failure")

    monkeypatch.setattr(YKAQR.qrcode, "QRCode", BrokenQRCode)

    with pytest.raises(ValueError, match="unrelated QR failure"):
        export_qr(QR_KIND_COMPRESSED_JSON, encode_j1('[["a",0,0]]'))


def test_dense_catalog_uses_c1_qr_when_j1_exceeds_capacity() -> None:
    root = Path(__file__).resolve().parents[1]
    catalog_path = root / "DatAnDict" / "YKACompactCatalog.json"
    registry_path = root / "DatAnDict" / "YKACompactRegistry.json"
    catalog = codec.load_catalog(catalog_path, registry_path)
    view = codec._catalog(catalog)
    rows: list[list[object]] = []
    for index, pool in enumerate(view.ordinary):
        points = codec._slot_points(pool, view.default_width, view.scale)
        coordinates = [value for point in points for value in point]
        row: list[object] = [
            pool["key"],
            (index * 7919) % 100003,
            (index * 7) % view.status_count,
        ]
        if coordinates:
            row.extend(("", coordinates))
        rows.append(row)
    rows.extend(
        [pool["key"], index % 2]
        for index, pool in enumerate(view.background)
    )
    raw = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    artifacts = codec.build_import_artifacts(
        raw,
        catalog_path=catalog_path,
        registry_path=registry_path,
        target_width=view.default_width,
        expected_pool_keys=tuple(str(row[0]) for row in rows),
    )

    with pytest.raises(QRCapacityError):
        export_qr(
            QR_KIND_COMPRESSED_JSON,
            artifacts.qr_payload(QR_KIND_COMPRESSED_JSON),
        )
    for kind in (QR_KIND_C1_BASE64, QR_KIND_C1_BASE4096):
        image, metadata = export_qr(kind, artifacts.qr_payload(kind))
        assert image.size[0] == metadata.pixels
        assert metadata.version <= 40


def test_qr_pixels_are_decodable_when_opencv_is_available() -> None:
    cv2 = pytest.importorskip("cv2")
    numpy = pytest.importorskip("numpy")
    payloads = {
        QR_KIND_COMPRESSED_JSON: encode_j1('[["a",0,0]]'),
        QR_KIND_C1_BASE64: encode_base64(_wire()),
        QR_KIND_C1_BASE4096: encode_base4096(_wire()),
    }
    detector = cv2.QRCodeDetector()
    for kind, payload in payloads.items():
        image, _ = export_qr(kind, payload)
        pixels = numpy.asarray(image.convert("RGB"))[:, :, ::-1]
        decoded, points, _ = detector.detectAndDecode(pixels)
        assert points is not None
        assert decoded == payload
