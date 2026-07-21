import hashlib
import json
import re
from pathlib import Path

import pytest

import YKACatalog as catalog_module
from YKACatalog import CatalogDecodeError, build, coordinate, load_fashion_catalog
from YKAWechatImport import _mark_coordinates


ROOT = Path(__file__).resolve().parents[1]


def test_catalog_shape_and_content_hash():
    c = json.loads(
        (ROOT / "DatAnDict" / "YKACompactCatalog.json").read_text(encoding="utf-8")
    )
    assert c["catalog_id"] == "00000100"
    assert len(c["ordinary"]) == 199
    assert len(c["background"]) == 126
    assert all(isinstance(v, int) for p in c["ordinary"] for pair in p["center_integer_pairs"] for v in pair)
    body = dict(c)
    body["content_sha256"] = ""
    digest = hashlib.sha256(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    assert digest == c["content_sha256"]


def test_rebuild_is_deterministic_and_verified_slots_only():
    c = build()
    assert c == build()
    for p in c["ordinary"]:
        assert p["n"] == len(p["slots"])
        assert p["n"] == len(p["center_integer_pairs"]) or p["n"] == 0


def test_coordinate_vectors_and_width_261_reference():
    c = build()
    source = json.loads(
        (ROOT / "DatAnDict" / "YKAPoolCatalog.json").read_text(encoding="utf-8")
    )
    by_key = {p["key"]: p for p in source["pools"]}
    for width in (120, 261, 1200):
        flat = []
        for p in c["ordinary"]:
            original = by_key[p["key"]]
            marks = [{"slot_index": i} for i in range(p["n"])]
            expected = _mark_coordinates(original, marks, width)
            local = []
            for center in p["center_integer_pairs"][: p["n"]]:
                point = coordinate(center, p["source"], width)
                local.extend(point)
                flat.extend(point)
            got_points = [tuple(local[i : i + 2]) for i in range(0, len(local), 2)]
            assert got_points == list(expected)
        got = hashlib.sha256(json.dumps(flat, separators=(",", ":")).encode()).hexdigest()
        assert got == c["coordinate_sha256"][str(width)]


def test_catalog_id_status_and_registry_hash():
    c = build()
    assert re.fullmatch(r"\d{8}", c["catalog_id"])
    assert c["status_schema"] == {"count": 11, "values": list(range(11))}
    registry = json.loads(
        (ROOT / "DatAnDict" / "YKACompactRegistry.json").read_text(encoding="utf-8")
    )
    assert registry["catalogs"][c["catalog_id"]] == c["content_sha256"]


def test_registry_rejects_duplicate_id_with_different_content(tmp_path, monkeypatch):
    import YKACatalog as builder

    out = tmp_path / "catalog.json"
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"schema_version": 1, "catalogs": {"00000100": "different"}}), encoding="utf-8")
    monkeypatch.setattr(builder, "OUT", out)
    monkeypatch.setattr(builder, "REGISTRY", registry)
    try:
        builder.main()
    except RuntimeError as exc:
        assert "different content" in str(exc)
    else:
        raise AssertionError("duplicate catalog id was accepted")


def test_fashion_catalog_rejects_an_invalid_package_header(tmp_path):
    package = tmp_path / "data.png"
    package.write_bytes(b"not-a-fashion-catalog")
    with pytest.raises(CatalogDecodeError, match="package header"):
        load_fashion_catalog(package)


def test_current_catalog_layout_skips_the_leading_compressed_table(
    tmp_path, monkeypatch
):
    package = tmp_path / "data.png"
    raw = bytearray(catalog_module.PACKAGE_HEADER_BYTES)
    raw[:4] = catalog_module.PACKAGE_MAGIC
    raw[4:12] = len(raw).to_bytes(8, "little")
    package.write_bytes(raw)

    offsets: list[int] = []
    streams = iter(
        [
            (b"leading", 310),
            (b"fashion", 320),
            (b"suite", 330),
        ]
    )

    def fake_inflate(_raw: bytes, offset: int):
        offsets.append(offset)
        return next(streams)

    parsed_tables: list[tuple[bytes, tuple[int, int]]] = []

    def fake_parse_table(blob, *, index_offset, expected, table_name):
        parsed_tables.append((blob, expected))
        if blob == b"fashion":
            return b"fashion", [(101, 0), (7, 7)]
        return b"suite", [(201, 0), (5, 5)]

    monkeypatch.setattr(catalog_module, "_inflate_at", fake_inflate)
    monkeypatch.setattr(catalog_module, "_parse_table", fake_parse_table)
    monkeypatch.setattr(
        catalog_module,
        "_parse_fashion",
        lambda fashion_id, _row: {"fashion_index": fashion_id, "suites": []},
    )
    monkeypatch.setattr(
        catalog_module,
        "_parse_suite",
        lambda suite_id, _row: {
            "suite_id": suite_id,
            "suite_name": "suite",
            "suite_type": 1,
            "quality": 1,
            "icon_id": 1,
            "main_fashion_id": 0,
            "items": [],
        },
    )

    result = load_fashion_catalog(package)

    assert offsets == [catalog_module.PACKAGE_HEADER_BYTES, 310, 320]
    assert parsed_tables == [
        (b"fashion", catalog_module.EXPECTED_FASHION_TABLE),
        (b"suite", catalog_module.EXPECTED_FASHION_SUITE_TABLE),
    ]
    assert result.metadata["parsed_package_end"] == 330
    assert result.entries == {101: {"fashion_index": 101, "suites": []}}


def test_pool_catalog_pins_the_current_installed_game_catalog():
    pool_catalog = json.loads(
        (ROOT / "DatAnDict" / "YKAPoolCatalog.json").read_text(encoding="utf-8")
    )

    assert pool_catalog["game_catalog"] == {
        "sha256": "01577A460786FB65978EAA9A11B9511726CF659BEFE3F937D2CD8FF17D536F18",
        "fashion_catalog_count": 9530,
    }
