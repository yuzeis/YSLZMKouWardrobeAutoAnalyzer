from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import zipfile

import pytest

from Packaging.YKABuildGiteeTree import (
    BuildOptions,
    MAX_GIT_FILE_BYTES,
    TreeBuildError,
    build_tree,
)


GENERATED_AT = datetime(2027, 1, 1, tzinfo=timezone.utc)


def _write(path: Path, value: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(value, encoding="utf-8", newline="\n")
    return path


def _config() -> dict[str, object]:
    return {
        "schema_version": 1,
        "config_version": 7,
        "config_id": "fixture-v00000007",
        "issued_at": "2026-12-01T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "target_package": "com.zulong.yslzm",
        "content_sha256": {
            "compatibility_profiles": "fixture",
            "compact_catalog": "fixture",
            "compact_registry": "fixture",
            "pool_catalog": "fixture",
        },
        "compatibility_profiles": {"schema_version": 1, "profiles": []},
        "compact_catalog": {"schema_version": 1, "catalog_id": "fixture"},
        "compact_registry": {"schema_version": 1, "catalogs": {}},
        "pool_catalog": {"schema_version": 5, "pools": []},
        "signature": {
            "algorithm": "RSA-3072-PKCS1-v1_5-SHA256",
            "key_id": "fixture-public-key",
            "value": "QUJDRA==",
        },
    }


def _fixture_roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    pc_root = tmp_path / "pc"
    android_root = tmp_path / "android"
    config_path = pc_root / "DatAnDict" / "YKAConfigBuiltin.json"
    config_bytes = (
        json.dumps(_config(), ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    trust_bytes = (
        json.dumps(
            {
                "schema_version": 1,
                "keys": [{"key_id": "fixture-public-key", "exponent": 65537}],
            },
            indent=2,
        )
        + "\n"
    ).encode("utf-8")

    _write(pc_root / "LICENSE", "GNU GENERAL PUBLIC LICENSE Version 2\n")
    _write(pc_root / "README.md", "# Fixture\n")
    _write(pc_root / "THIRD_PARTY_NOTICES.md", "Scapy | GPL-2.0-only\n")
    _write(pc_root / "YKAApp.py", "def main():\n    return 0\n")
    _write(
        pc_root / "YKAConfigManager.py",
        "def load_config():\n    return {}\n",
    )
    _write(pc_root / "YKAReport.py", "def render():\n    return {}\n")
    _write(pc_root / "YKARequirementsLock.txt", "scapy==2.7.0\n")
    _write(config_path, config_bytes)
    _write(pc_root / "DatAnDict" / "YKAConfigTrust.json", trust_bytes)
    _write(pc_root / "Docs" / "guide.md", "# Guide\n")
    _write(
        pc_root / "Packaging" / "YSLZMKouWardrobeAutoAnalyzer.spec",
        "name = 'fixture'\n",
    )
    _write(
        pc_root / "Test" / "YKATestConfigManager.py",
        "def test_fixture_config_manager():\n    assert True\n",
    )

    _write(android_root / "COPYING", "GNU GENERAL PUBLIC LICENSE Version 3\n")
    _write(android_root / "THIRD_PARTY_NOTICES.md", "Fixture notices\n")
    _write(android_root / "UPSTREAM.md", "Fixture upstream\n")
    _write(android_root / "build.gradle", "// fixture\n")
    _write(android_root / "gradle.properties", "fixture=true\n")
    _write(android_root / "gradlew", "#!/bin/sh\n")
    _write(android_root / "gradlew.bat", "@echo off\r\n")
    _write(android_root / "settings.gradle", "include ':app'\n")
    _write(android_root / "app" / "build.gradle", "// fixture\n")
    _write(
        android_root / "app" / "src" / "main" / "AndroidManifest.xml",
        "<manifest package=\"fixture.safe\" />\n",
    )
    _write(
        android_root
        / "app"
        / "src"
        / "main"
        / "java"
        / "fixture"
        / "CaptureService.java",
        "package fixture;\npublic final class CaptureService {}\n",
    )
    asset_root = android_root / "app" / "src" / "main" / "assets" / "yka"
    _write(asset_root / "YKAConfigBuiltin.json", config_bytes)
    _write(asset_root / "YKAConfigTrust.json", trust_bytes)
    return pc_root, android_root, config_path


def _release_apk(path: Path, *, debug: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        certificate = b"Android Debug" if debug else b"YKA Release Certificate"
        archive.writestr("META-INF/CERT.RSA", certificate)
        archive.writestr("classes.dex", b"dex\nfixture")
    return path


def _signed_pe(path: Path, *, signed: bool = True) -> Path:
    data = bytearray(512)
    data[:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<H", data, file_header, 0x8664)
    struct.pack_into("<H", data, file_header + 16, 224)
    optional = file_header + 20
    struct.pack_into("<H", data, optional, 0x10B)
    if signed:
        struct.pack_into("<II", data, optional + 96 + (4 * 8), 400, 16)
        struct.pack_into("<IHH", data, 400, 16, 0x0200, 0x0002)
    return _write(path, bytes(data))


def _options(
    *,
    pc_root: Path,
    android_root: Path,
    config_path: Path,
    output: Path,
    artifacts: tuple[Path, ...] = (),
    strict: bool = False,
) -> BuildOptions:
    return BuildOptions(
        pc_root=pc_root,
        android_root=android_root,
        config_source=config_path,
        output=output,
        release_id="fixture-release",
        artifacts=artifacts,
        strict_release=strict,
        generated_at=GENERATED_AT,
    )


def _issue_codes(error: TreeBuildError) -> set[str]:
    return {issue.code for issue in error.issues}


def test_builds_exact_source_config_and_release_shape_without_binaries(
    tmp_path: Path,
) -> None:
    pc_root, android_root, config_path = _fixture_roots(tmp_path)
    _write(pc_root / "Build" / "private.exe", b"not selected")
    _write(android_root / "evidence" / "capture.pcapng", b"not selected")
    _write(android_root / ".gradle-local" / "cache.bin", b"not selected")
    _write(
        android_root
        / "app"
        / "src"
        / "main"
        / "jni"
        / "tests"
        / "pcap"
        / "fixture.pcap",
        b"not selected",
    )
    apk = _release_apk(tmp_path / "artifacts" / "fixture-release.apk")
    exe = _signed_pe(tmp_path / "artifacts" / "fixture-release.exe")
    output = tmp_path / "publication"

    result = build_tree(
        _options(
            pc_root=pc_root,
            android_root=android_root,
            config_path=config_path,
            output=output,
            artifacts=(apk, exe),
        )
    )

    assert result["artifact_count"] == 2
    assert (output / "src" / "pc" / "YKAApp.py").is_file()
    assert (output / "src" / "pc" / "YKAConfigManager.py").is_file()
    assert (
        output / "src" / "pc" / "Test" / "YKATestConfigManager.py"
    ).is_file()
    assert (
        output
        / "src"
        / "android"
        / "app"
        / "src"
        / "main"
        / "AndroidManifest.xml"
    ).is_file()
    assert (output / "config" / "latest.json").read_bytes() == config_path.read_bytes()
    assert {path.name for path in (output / "release").iterdir()} == {
        "index.json",
        "SHA256SUMS.txt",
    }
    assert not list(output.rglob("*.apk"))
    assert not list(output.rglob("*.exe"))
    assert not list(output.rglob("*.pcap*"))

    index = json.loads((output / "release" / "index.json").read_text())
    assert [item["name"] for item in index["artifacts"]] == [
        "fixture-release.apk",
        "fixture-release.exe",
    ]
    assert all(
        item["delivery"] == "gitee-release-attachment"
        for item in index["artifacts"]
    )
    sums = (output / "release" / "SHA256SUMS.txt").read_text()
    assert hashlib.sha256(apk.read_bytes()).hexdigest().upper() in sums
    assert hashlib.sha256(exe.read_bytes()).hexdigest().upper() in sums


def test_accepts_an_existing_empty_output_directory(tmp_path: Path) -> None:
    pc_root, android_root, config_path = _fixture_roots(tmp_path)
    output = tmp_path / "publication"
    output.mkdir()

    build_tree(
        _options(
            pc_root=pc_root,
            android_root=android_root,
            config_path=config_path,
            output=output,
        )
    )

    assert (output / "release" / "index.json").is_file()


def test_rejects_config_without_compact_registry(tmp_path: Path) -> None:
    pc_root, android_root, config_path = _fixture_roots(tmp_path)
    incomplete = _config()
    incomplete.pop("compact_registry")
    _write(
        config_path,
        json.dumps(incomplete, ensure_ascii=False, indent=2) + "\n",
    )

    with pytest.raises(TreeBuildError) as caught:
        build_tree(
            _options(
                pc_root=pc_root,
                android_root=android_root,
                config_path=config_path,
                output=tmp_path / "publication",
            )
        )

    assert "CONFIG_MISSING_REQUIRED_FIELDS" in _issue_codes(caught.value)
    assert not (tmp_path / "publication").exists()


def test_rejects_a_nonempty_output_without_touching_it(tmp_path: Path) -> None:
    pc_root, android_root, config_path = _fixture_roots(tmp_path)
    output = tmp_path / "publication"
    marker = _write(output / "keep.txt", "keep\n")

    with pytest.raises(TreeBuildError) as caught:
        build_tree(
            _options(
                pc_root=pc_root,
                android_root=android_root,
                config_path=config_path,
                output=output,
            )
        )

    assert "OUTPUT_NOT_EMPTY_DIRECTORY" in _issue_codes(caught.value)
    assert marker.read_text() == "keep\n"


@pytest.mark.parametrize(
    ("content", "expected_code"),
    [
        ("phone=" + "156" + "000" + "00000", "SUSPECTED_PHONE_NUMBER"),
        (
            "identity=" + "765" + "4321" + "$zulong@1091",
            "SUSPECTED_ACCOUNT_ID",
        ),
        (
            "api_" + "key = \"" + ("s" * 24) + "\"",
            "SUSPECTED_SECRET",
        ),
        (
            "token=" + "ghp" + "_" + ("A" * 24),
            "SUSPECTED_ACCESS_TOKEN",
        ),
        (
            "https://" + "name:" + "credential" + "@example.invalid/path",
            "CREDENTIAL_URL",
        ),
        (
            "path=" + "C:" + "\\Users\\fixture\\capture.bin",
            "ABSOLUTE_LOCAL_PATH",
        ),
        (
            "-----BEGIN " + "PRIVATE KEY-----",
            "PRIVATE_KEY_CONTENT",
        ),
    ],
)
def test_selected_sensitive_content_fails_closed(
    tmp_path: Path,
    content: str,
    expected_code: str,
) -> None:
    pc_root, android_root, config_path = _fixture_roots(tmp_path)
    _write(pc_root / "README.md", content + "\n")

    with pytest.raises(TreeBuildError) as caught:
        build_tree(
            _options(
                pc_root=pc_root,
                android_root=android_root,
                config_path=config_path,
                output=tmp_path / "publication",
            )
        )

    assert expected_code in _issue_codes(caught.value)
    assert not (tmp_path / "publication").exists()


def test_selected_file_over_50_mib_fails_before_copy(tmp_path: Path) -> None:
    pc_root, android_root, config_path = _fixture_roots(tmp_path)
    large = pc_root / "Docs" / "large.md"
    large.parent.mkdir(parents=True, exist_ok=True)
    with large.open("wb") as stream:
        stream.truncate(MAX_GIT_FILE_BYTES + 1)

    with pytest.raises(TreeBuildError) as caught:
        build_tree(
            _options(
                pc_root=pc_root,
                android_root=android_root,
                config_path=config_path,
                output=tmp_path / "publication",
            )
        )

    assert "GIT_FILE_OVER_50_MIB" in _issue_codes(caught.value)
    assert not (tmp_path / "publication").exists()


def test_strict_release_accepts_clean_fixture_and_release_signing(
    tmp_path: Path,
) -> None:
    pc_root, android_root, config_path = _fixture_roots(tmp_path)
    apk = _release_apk(tmp_path / "artifacts" / "fixture-release.apk")
    exe = _signed_pe(tmp_path / "artifacts" / "fixture-release.exe")
    output = tmp_path / "publication"

    result = build_tree(
        _options(
            pc_root=pc_root,
            android_root=android_root,
            config_path=config_path,
            output=output,
            artifacts=(apk, exe),
            strict=True,
        )
    )

    assert result["strict_release"] is True
    index = json.loads((output / "release" / "index.json").read_text())
    assert index["strict_release"] is True


def test_strict_release_aggregates_current_class_blockers(tmp_path: Path) -> None:
    pc_root, android_root, config_path = _fixture_roots(tmp_path)
    _write(pc_root / "LICENSE", "GNU AFFERO GENERAL PUBLIC LICENSE Version 3\n")
    (android_root / "THIRD_PARTY_NOTICES.md").unlink()
    _write(
        android_root
        / "app"
        / "src"
        / "main"
        / "res"
        / "values"
        / "strings.xml",
        "<resources><string name=\"license\">"
        "GNU Affero General Public License"
        "</string></resources>\n",
    )
    _write(
        android_root / "ICONS_LICENSE" / "app_icon" / "Attribution.txt",
        "Icon from Freepik; Attribution-NonCommercial\n",
    )
    _write(
        android_root
        / "app"
        / "src"
        / "main"
        / "res"
        / "raw"
        / "capture.ogg",
        b"OggSfixture",
    )
    apk = _release_apk(
        tmp_path / "artifacts" / "fixture-debug.apk",
        debug=True,
    )
    exe = _signed_pe(
        tmp_path / "artifacts" / "fixture-release.exe",
        signed=False,
    )

    with pytest.raises(TreeBuildError) as caught:
        build_tree(
            _options(
                pc_root=pc_root,
                android_root=android_root,
                config_path=config_path,
                output=tmp_path / "publication",
                artifacts=(apk, exe),
                strict=True,
            )
        )

    assert {
        "PC_AGPL_SCAPY_GPL2_ONLY_CONFLICT",
        "ANDROID_THIRD_PARTY_NOTICES_MISSING",
        "ANDROID_LICENSE_DECLARATIONS_MIXED",
        "ANDROID_NONCOMMERCIAL_ICON_ASSET",
        "ANDROID_AUDIO_LICENSE_MISSING",
        "ANDROID_DEBUG_SIGNING_BLOCKED",
        "WINDOWS_AUTHENTICODE_MISSING",
    }.issubset(_issue_codes(caught.value))
    assert not (tmp_path / "publication").exists()
