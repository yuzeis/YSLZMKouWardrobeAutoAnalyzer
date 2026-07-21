import hashlib
import json
import re
from pathlib import Path

import pytest

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
