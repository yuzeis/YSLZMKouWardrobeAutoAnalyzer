from __future__ import annotations

import json
import itertools
import random
import zlib
from pathlib import Path

import pytest

import YKACompactCodec as codec


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "DatAnDict" / "YKACompactCatalog.json"
REGISTRY = ROOT / "DatAnDict" / "YKACompactRegistry.json"


@pytest.fixture
def catalog() -> dict[str, object]:
    scale = 1_000_000
    source = [1000, 500]

    def pool(key: str, centers: list[list[int]]) -> dict[str, object]:
        points = []
        for center in centers:
            x = (2 * center[0] * 120 - 50 * scale + scale) // (2 * scale)
            y = (
                2 * center[1] * 500 * 120 - 50 * scale * 1000 + scale * 1000
            ) // (2 * scale * 1000)
            points.append([x, y])
        return {
            "key": key,
            "n": len(centers),
            "slots": points,
            "source": source,
            "center_integer_pairs": centers,
        }

    result = {
        "catalog_id": "12345678",
        "default_width": 120,
        "status_count": 3,
        "scale": scale,
        "ordinary": [
            pool("a", [[100000, 100000], [300000, 100000], [500000, 100000], [700000, 100000]]),
            pool("b", [[200000, 300000], [400000, 300000]]),
            pool("c", []),
        ],
        "background": [{"key": "bg1"}, {"key": "bg2"}],
    }
    result["content_sha256"] = codec._content_hash(result)
    return result


def _points(catalog: dict[str, object], pool_index: int, width: int = 120) -> list[int]:
    view = codec._catalog(catalog)
    return [value for point in codec._slot_points(view.ordinary[pool_index], width, view.scale) for value in point]


@pytest.mark.parametrize(
    ("rows", "expected_codec"),
    (
        ([['a', 0, 0], ['b', 0, 1], ['c', 0, 2]], 0),
        ([['a', 0, 0], ['b', 0, 1], ['c', 0, 2], ['bg1', 1], ['bg2', 0]], 1),
        ([['a', 23, 0], ['b', 0, 1], ['c', 1, 2]], 2),
        ([['a', 23, 0], ['b', 0, 1], ['c', 1, 2], ['bg1', 1], ['bg2', 0]], 3),
    ),
)
def test_all_codec_variants_round_trip(
    catalog: dict[str, object],
    rows: list[list[object]],
    expected_codec: int,
) -> None:
    text = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    wire = codec.encode(text, catalog)
    assert wire[4] == expected_codec
    assert codec.decode(wire, catalog) == text


def test_none_all_mixed_and_width_override_round_trip(catalog: dict[str, object]) -> None:
    points_a = _points(catalog, 0, width=261)
    points_b = _points(catalog, 1, width=261)
    rows = [
        ["a", 460, 2, "", points_a[0:2] + points_a[4:6]],
        ["b", 2, 1, "", points_b],
        ["c", 0, 0],
        ["bg1", 0],
        ["bg2", 1],
    ]
    text = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    wire = codec.encode(text, catalog, target_width=261)
    assert codec.decode(wire, catalog) == text


def test_comb_and_raw_subset_paths_are_canonical() -> None:
    for n, selected, expected_tag in ((16, [0], 0), (16, list(range(0, 16, 2)), 1)):
        writer = codec._BitWriter()
        codec._write_subset(writer, n, selected)
        reader = codec._BitReader(writer.to_bytes())
        assert reader.read_bits(1) == 1
        assert reader.read_bits(1) == expected_tag
        reader = codec._BitReader(writer.to_bytes())
        assert codec._read_subset(reader, n) == selected


@pytest.mark.parametrize(
    "bad_rows",
    (
        [["b", 0, 0], ["a", 0, 0], ["c", 0, 0]],
        [["a", True, 0], ["b", 0, 0], ["c", 0, 0]],
        [["a", 0, False], ["b", 0, 0], ["c", 0, 0]],
        [["a", 0.0, 0], ["b", 0, 0], ["c", 0, 0]],
        [["a", 0, 0], ["b", 0, 0], ["c", 0, 0], ["bg1", 1]],
        [["a", 0, 0], ["b", 0, 0], ["c", 0, 0], ["bg2", 0], ["bg1", 1]],
    ),
)
def test_noncanonical_rows_are_rejected(
    catalog: dict[str, object],
    bad_rows: list[list[object]],
) -> None:
    with pytest.raises(codec.CodecError):
        codec.encode(json.dumps(bad_rows, separators=(",", ":")), catalog)


def test_draw_count_bounds_and_gamma(catalog: dict[str, object]) -> None:
    rows = [["a", codec.MAX_SAFE_INTEGER, 0], ["b", 1, 1], ["c", 0, 2]]
    text = json.dumps(rows, separators=(",", ":"))
    assert codec.decode(codec.encode(text, catalog), catalog) == text
    rows[0][1] = codec.MAX_SAFE_INTEGER + 1
    with pytest.raises(codec.CodecError):
        codec.encode(json.dumps(rows, separators=(",", ":")), catalog)


def test_crc_header_padding_and_unknown_codec_rejected(catalog: dict[str, object]) -> None:
    text = '[["a",23,0],["b",0,1],["c",0,2]]'
    wire = bytearray(codec.encode(text, catalog))
    corrupted = bytearray(wire)
    corrupted[-1] ^= 1
    with pytest.raises(codec.CodecError, match="CRC"):
        codec.decode(corrupted, catalog)

    invalid_bcd = bytearray(wire)
    invalid_bcd[0] = 0xA1
    with pytest.raises(codec.CodecError, match="BCD"):
        codec.decode(invalid_bcd, catalog)

    unknown_codec = bytearray(wire)
    unknown_codec[4] = 9
    with pytest.raises(codec.CodecError, match="codec"):
        codec.decode(unknown_codec, catalog)

    extra_zero = bytearray(wire + b"\x00")
    payload = bytes(extra_zero[9:])
    checksum = zlib.crc32(codec.HEADER_DOMAIN + bytes(extra_zero[:5]) + payload) & 0xFFFFFFFF
    extra_zero[5:9] = checksum.to_bytes(4, "big")
    with pytest.raises(codec.CodecError, match="多余"):
        codec.decode(extra_zero, catalog)


def test_catalog_id_and_content_hash_are_strict(catalog: dict[str, object]) -> None:
    invalid = dict(catalog)
    invalid["catalog_id"] = 12345678
    with pytest.raises(codec.CodecError, match="8 位"):
        codec.encode('[["a",0,0],["b",0,0],["c",0,0]]', invalid)

    invalid = dict(catalog)
    invalid["content_sha256"] = "0" * 64
    with pytest.raises(codec.CodecError, match="content_sha256"):
        codec.encode('[["a",0,0],["b",0,0],["c",0,0]]', invalid)


def test_truncated_binary_exhaustive() -> None:
    for count in range(1, 65):
        for value in range(count):
            writer = codec._BitWriter()
            codec._write_truncated(writer, value, count)
            reader = codec._BitReader(writer.to_bytes())
            assert codec._read_truncated(reader, count) == value
            assert reader.position == codec._truncated_length(value, count)


def test_combination_rank_unrank_exhaustive() -> None:
    for n in range(11):
        for k in range(n + 1):
            combinations = list(itertools.combinations(range(n), k))
            for expected_rank, selected in enumerate(combinations):
                assert codec._rank_combination(n, k, selected) == expected_rank
                assert codec._unrank_combination(n, k, expected_rank) == list(selected)


def test_histogram_rank_unrank_exhaustive() -> None:
    for pool_count in range(6):
        for status_count in range(1, 5):
            compositions = [
                values
                for values in itertools.product(
                    range(pool_count + 1),
                    repeat=status_count,
                )
                if sum(values) == pool_count
            ]
            ranks = [
                codec._rank_histogram(values, pool_count, status_count)
                for values in compositions
            ]
            assert sorted(ranks) == list(range(len(compositions)))
            for values, rank in zip(compositions, ranks):
                assert codec._unrank_histogram(
                    pool_count,
                    status_count,
                    rank,
                ) == list(values)


@pytest.mark.parametrize(
    "counts",
    (
        [4],
        [2, 2],
        [3, 2, 1],
        [2, 2, 2],
    ),
)
def test_sequence_rank_unrank_exhaustive(counts: list[int]) -> None:
    source = [status for status, count in enumerate(counts) for _ in range(count)]
    sequences = sorted(set(itertools.permutations(source)))
    ranks = [codec._rank_sequence(sequence, counts) for sequence in sequences]
    assert sorted(ranks) == list(range(len(sequences)))
    for sequence, rank in zip(sequences, ranks):
        assert codec._unrank_sequence(counts, rank) == list(sequence)


def test_subset_round_trip_exhaustive() -> None:
    for n in range(11):
        for mask in range(1 << n):
            selected = [index for index in range(n) if mask & (1 << index)]
            writer = codec._BitWriter()
            codec._write_subset(writer, n, selected)
            reader = codec._BitReader(writer.to_bytes())
            assert codec._read_subset(reader, n) == selected


def test_catalog_without_background_round_trip(catalog: dict[str, object]) -> None:
    catalog = dict(catalog)
    catalog["background"] = []
    catalog["content_sha256"] = codec._content_hash(catalog)
    text = '[["a",23,0],["b",0,1],["c",0,2]]'
    wire = codec.encode(text, catalog)
    assert wire[4] == 2
    assert codec.decode(wire, catalog) == text


def test_default_width_override_is_noncanonical(catalog: dict[str, object]) -> None:
    text = '[["a",0,0],["b",0,1],["c",0,2]]'
    wire = bytearray(codec.encode(text, catalog, target_width=121))
    wire[10] &= 0xEF
    payload = bytes(wire[9:])
    checksum = zlib.crc32(codec.HEADER_DOMAIN + bytes(wire[:5]) + payload) & 0xFFFFFFFF
    wire[5:9] = checksum.to_bytes(4, "big")
    with pytest.raises(codec.CodecError, match="默认宽度"):
        codec.decode(wire, catalog)


def test_base64_strict_round_trip_and_rejections() -> None:
    for payload in (b"", b"a", b"ab", b"abc", bytes(range(256))):
        assert codec.decode_base64(codec.encode_base64(payload)) == payload
    for invalid in (" YQ==", "YQ==\n", "YQ", "YQ=", "YQ===", "YQ-_"):
        with pytest.raises(codec.TransportError):
            codec.decode_base64(invalid)


def test_base4096_round_trip_and_strict_alphabet() -> None:
    randomizer = random.Random(20260720)
    payloads = [b"", b"abc", b"a\x80b"]
    payloads.extend(randomizer.randbytes(length) for length in range(1, 65))
    for payload in payloads:
        encoded = codec.encode_base4096(payload)
        assert codec.decode_base4096(encoded) == payload
    with pytest.raises(codec.TransportError):
        codec.decode_base4096("")
    with pytest.raises(codec.TransportError):
        codec.decode_base4096(chr(codec.BASE4096_END + 1))


def test_base45_known_vectors_and_invalid_values() -> None:
    assert codec.base45_encode(b"AB") == "BB8"
    assert codec.base45_decode("BB8") == b"AB"
    assert codec.base45_encode(b"Hello!!") == "%69 VD92EX0"
    assert codec.base45_decode("%69 VD92EX0") == b"Hello!!"
    with pytest.raises(codec.TransportError):
        codec.base45_decode("A")
    with pytest.raises(codec.TransportError):
        codec.base45_decode(":::")


def test_j1_canonical_json_round_trip_and_integrity() -> None:
    text = '[["pool",23,1,"",[25,25]],["bg1",1]]'
    code = codec.encode_j1(text)
    assert code.startswith(f"J1:{len(text.encode('utf-8'))}:")
    assert codec.decode_j1(code) == text
    with pytest.raises(codec.TransportError):
        codec.encode_j1('[ ["pool", 23, 1] ]')
    with pytest.raises(codec.TransportError):
        codec.encode_j1('{"not":"an array"}')
    parts = code.split(":", 3)
    with pytest.raises(codec.TransportError):
        codec.decode_j1(f"{parts[0]}:{parts[1]}:00000000:{parts[3]}")
    with pytest.raises(codec.TransportError):
        codec.decode_j1(code[:-1])


def _all_zero_code(*, draw_count: int = 0) -> str:
    catalog_data = json.loads(CATALOG.read_text(encoding="utf-8"))
    rows = [
        [pool["key"], draw_count if index == 0 else 0, index % 11]
        for index, pool in enumerate(catalog_data["ordinary"])
    ]
    rows.extend(
        [background["key"], 0]
        for background in catalog_data["background"]
    )
    return json.dumps(rows, ensure_ascii=False, separators=(",", ":"))


def test_artifacts_are_generated_atomically_and_preserve_draw_counts() -> None:
    code = _all_zero_code(draw_count=460)
    artifacts = codec.build_import_artifacts(
        code,
        catalog_path=CATALOG,
        registry_path=REGISTRY,
        target_width=261,
    )
    assert artifacts.raw_json == code
    assert artifacts.codec_id == 3
    assert artifacts.catalog_id == "00000102"
    assert len(artifacts.compressed_json) < len(code)
    assert len(artifacts.c1_base4096) < len(artifacts.c1_base64)
    with pytest.raises(codec.ArtifactError, match="原始 JSON"):
        artifacts.qr_payload("原始 JSON")


def test_artifact_generation_rejects_noncanonical_json() -> None:
    with pytest.raises(codec.ArtifactError):
        codec.build_import_artifacts(
            '[ ["bad", 0, 0] ]',
            catalog_path=CATALOG,
            registry_path=REGISTRY,
            target_width=261,
        )


def test_artifact_generation_rejects_cross_catalog_key_order_mismatch() -> None:
    code = _all_zero_code()
    rows = json.loads(code)
    source_keys = [str(row[0]) for row in rows]
    source_keys[0], source_keys[1] = source_keys[1], source_keys[0]

    with pytest.raises(codec.ArtifactError, match="键序不一致"):
        codec.build_import_artifacts(
            code,
            catalog_path=CATALOG,
            registry_path=REGISTRY,
            target_width=261,
            expected_pool_keys=source_keys,
        )
