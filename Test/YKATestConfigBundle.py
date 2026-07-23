from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROJECT_ROOT.parent
BUNDLE_PATH = PROJECT_ROOT / "DatAnDict" / "YKAConfigBuiltin.json"
TRUST_PATH = PROJECT_ROOT / "DatAnDict" / "YKAConfigTrust.json"
ANDROID_ASSET_ROOT = (
    WORKSPACE_ROOT
    / "YKAPhone-ver1.0-Preview"
    / "app"
    / "src"
    / "main"
    / "assets"
    / "yka"
)
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _load_bundle() -> tuple[dict[str, object], dict[str, object]]:
    bundle = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))
    trust = json.loads(TRUST_PATH.read_text(encoding="utf-8"))
    assert isinstance(bundle, dict)
    assert isinstance(trust, dict)
    return bundle, trust


def _verify_signature(bundle: dict[str, object], trust: dict[str, object]) -> None:
    signed = dict(bundle)
    signature = signed.pop("signature")
    assert isinstance(signature, dict)
    keys = trust["keys"]
    assert isinstance(keys, list)
    key = next(
        item
        for item in keys
        if isinstance(item, dict) and item.get("key_id") == signature.get("key_id")
    )
    modulus = int(str(key["modulus_hex"]), 16)
    exponent = int(key["exponent"])
    signature_bytes = base64.b64decode(str(signature["value"]), validate=True)
    encoded = pow(int.from_bytes(signature_bytes, "big"), exponent, modulus).to_bytes(
        (modulus.bit_length() + 7) // 8,
        "big",
    )
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(
        _canonical_bytes(signed)
    ).digest()
    padding_length = len(encoded) - len(digest_info) - 3
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    assert padding_length >= 8
    assert encoded == expected


def test_builtin_bundle_is_signed_and_self_consistent() -> None:
    bundle, trust = _load_bundle()
    assert BUNDLE_PATH.stat().st_size <= MAX_BUNDLE_BYTES
    assert bundle["schema_version"] == 1
    assert int(bundle["config_version"]) >= 1
    assert bundle["target_package"] == "com.zulong.yslzm"
    assert set(bundle["content_sha256"]) == {
        "compatibility_profiles",
        "compact_catalog",
        "compact_registry",
        "pool_catalog",
    }
    for section_name, expected in bundle["content_sha256"].items():
        actual = hashlib.sha256(_canonical_bytes(bundle[section_name])).hexdigest()
        assert actual.upper() == expected
    _verify_signature(bundle, trust)


@pytest.mark.skipif(
    not (ANDROID_ASSET_ROOT / "YKAConfigBuiltin.json").is_file()
    or not (ANDROID_ASSET_ROOT / "YKAConfigTrust.json").is_file(),
    reason="optional Android sibling checkout is not available",
)
def test_android_and_pc_embed_identical_bundle_and_trust_root() -> None:
    assert (
        ANDROID_ASSET_ROOT / "YKAConfigBuiltin.json"
    ).read_bytes() == BUNDLE_PATH.read_bytes()
    assert (
        ANDROID_ASSET_ROOT / "YKAConfigTrust.json"
    ).read_bytes() == TRUST_PATH.read_bytes()


def test_signature_rejects_tampered_embedded_content() -> None:
    bundle, trust = _load_bundle()
    tampered = json.loads(json.dumps(bundle))
    tampered["target_package"] = "example.invalid"
    try:
        _verify_signature(tampered, trust)
    except AssertionError:
        return
    raise AssertionError("tampered bundle unexpectedly passed signature verification")
