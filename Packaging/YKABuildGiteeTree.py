from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import sys
import tempfile
from typing import Iterable, Sequence
import zipfile


MAX_GIT_FILE_BYTES = 50 * 1024 * 1024
MAX_RELEASE_ATTACHMENT_BYTES = 100 * 1024 * 1024

PC_ROOT_FILES = (
    ".gitattributes",
    ".gitignore",
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "RELEASE_NOTES.md",
    "THIRD_PARTY_NOTICES.md",
    "YKAApp.py",
    "YKABusiness.py",
    "YKACapture.py",
    "YKACatalog.py",
    "YKACollector.py",
    "YKACompactCodec.py",
    "YKACompatibility.py",
    "YKAConfigManager.py",
    "YKACore.py",
    "YKAEnvironment.py",
    "YKAOpcodeResolver.py",
    "YKAProtocol.py",
    "YKAQR.py",
    "YKAReport.py",
    "YKAReplay.py",
    "YKAStart.bat",
    "YKATheme.py",
    "YKAWechatImport.py",
    "YKARequirements.txt",
    "YKARequirementsBuildLock.txt",
    "YKARequirementsDev.txt",
    "YKARequirementsLock.txt",
)

PC_DATA_FILES = (
    "YKACompactCatalog.json",
    "YKACompactRegistry.json",
    "YKACompatibilityProfiles.json",
    "YKAConfigBuiltin.json",
    "YKAConfigTrust.json",
    "YKAPoolCatalog.json",
)

PC_PACKAGING_FILES = (
    "README.md",
    "YKABuildGiteeTree.md",
    "YKABuildGiteeTree.py",
    "YKABuildSignedConfig.py",
    "YKAWindowsVersionInfo.txt",
    "YSLZMKouWardrobeAutoAnalyzer.spec",
)

PC_TEST_FILES = (
    "YKATestApp.py",
    "YKATestCapture.py",
    "YKATestCaptureFeedback.py",
    "YKATestCatalog.py",
    "YKATestCompact.py",
    "YKATestCompatibility.py",
    "YKATestConfigBundle.py",
    "YKATestConfigManager.py",
    "YKATestCore.py",
    "YKATestEnvironment.py",
    "YKATestGiteeTree.py",
    "YKATestProtocol.py",
    "YKATestQR.py",
    "YKATestReport.py",
    "YKATestReplay.py",
    "YKATestTheme.py",
    "YKATestWechatImport.py",
    "YKATestWechatValidation.py",
)

ANDROID_ROOT_FILES = (
    ".gitignore",
    "AUDIO_LICENSES.md",
    "CHANGELOG.md",
    "COPYING",
    "LICENSE_SCOPE.md",
    "THIRD_PARTY_NOTICES.md",
    "UPSTREAM.lock",
    "UPSTREAM.md",
    "build.gradle",
    "gradle.properties",
    "gradlew",
    "gradlew.bat",
    "settings.gradle",
)

ANDROID_APP_FILES = (
    "build.gradle",
    "proguard-rules.pro",
)

GLOBAL_PRUNED_DIR_NAMES = frozenset(
    {
        ".codex",
        ".codex-recovery",
        ".codex-remote-attachments",
        ".cxx",
        ".externalnativebuild",
        ".git",
        ".gradle",
        ".gradle-user",
        ".idea",
        ".pytest_cache",
        "__pycache__",
        "backups",
        "build",
        "cache",
        "caches",
        "captures",
        "dist",
        "downloads",
        "evidence",
        "keystore",
        "logs",
        "pcap",
        "reports",
        "screenshots",
        "secrets",
        ".ssh",
        "tmp",
    }
)

VENDOR_PRUNED_DIR_NAMES = frozenset(
    {
        "benchmark",
        "benchmarks",
        "corpus",
        "dga",
        "example",
        "examples",
        "fuzz",
        "lists",
        "packages",
        "test",
        "testprogs",
        "tests",
    }
)

FORBIDDEN_SUFFIXES = frozenset(
    {
        ".aab",
        ".apk",
        ".cap",
        ".dmp",
        ".exe",
        ".jks",
        ".key",
        ".keystore",
        ".log",
        ".msi",
        ".obb",
        ".p12",
        ".pcap",
        ".pcapng",
        ".pem",
        ".pfx",
        ".wxapkg",
    }
)

FORBIDDEN_EXACT_NAMES = frozenset(
    {
        ".env",
        ".netrc",
        "app-service.js",
        "auth.json",
        "auth.toml",
        "clipboard.txt",
        "commands.jsonl",
        "credentials",
        "data.png",
        "global-metadata.dat",
        "id_ed25519",
        "id_rsa",
        "libil2cpp.so",
        "local.properties",
        "metadata.json",
        "rec.md",
        "report.json",
        "yka-auto-metadata.json",
        "yka-auto-report.json",
    }
)

TEXT_SUFFIXES = frozenset(
    {
        "",
        ".am",
        ".bat",
        ".c",
        ".cc",
        ".cfg",
        ".cmake",
        ".conf",
        ".cpp",
        ".gradle",
        ".h",
        ".hpp",
        ".in",
        ".ini",
        ".java",
        ".json",
        ".md",
        ".mk",
        ".pro",
        ".properties",
        ".py",
        ".rules",
        ".sh",
        ".spec",
        ".toml",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)

PHONE_RE = re.compile(r"(?<![0-9])1[3-9][0-9]{9}(?![0-9])")
ACCOUNT_IDENTITY_RE = re.compile(r"(?<![0-9])[0-9]{5,20}\$zulong@")
ACCOUNT_FIELD_RE = re.compile(
    r"""(?ix)
    (?:
        ["']?(?:account[_-]?id|user[_-]?id|openid|unionid)["']?
        |(?:account|user|\u8d26\u53f7)
    )
    \s*[:=]\s*
    ["']?[0-9]{5,20}["']?
    """
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:ENCRYPTED |RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    ["']?
    (?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|
       refresh[_-]?token|authorization)
    ["']?
    \s*[:=]\s*
    ["'][^"' \t\r\n]{8,}["']
    """
)
BEARER_RE = re.compile(r"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]{20,}")
KNOWN_TOKEN_RE = re.compile(
    r"(?i)\b(?:ghp|github_pat|glpat|gitee)_[A-Za-z0-9_-]{16,}\b"
)
AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
CREDENTIAL_URL_RE = re.compile(r"(?i)https?://[^ /:@]+:[^ /@]+@")
WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/]")
UNC_PATH_RE = re.compile(r"\\\\[^\\\s]+\\[^\\\s]+")
POSIX_LOCAL_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:home|Users|tmp|private)/")
FILE_URL_RE = re.compile(r"(?i)\bfile:" + r"//")


class TreeBuildError(RuntimeError):
    def __init__(self, issues: Iterable["Issue"]):
        self.issues = tuple(sorted(set(issues), key=lambda item: (item.code, item.path)))
        summary = "; ".join(
            f"{issue.code}:{issue.path}" if issue.path else issue.code
            for issue in self.issues
        )
        super().__init__(summary or "release tree build failed")


@dataclass(frozen=True, order=True)
class Issue:
    code: str
    path: str = ""


@dataclass(frozen=True)
class CopyItem:
    source: Path
    destination: PurePosixPath


@dataclass(frozen=True)
class ArtifactRecord:
    path: Path
    name: str
    size: int
    sha256: str
    media_type: str


@dataclass(frozen=True)
class BuildOptions:
    pc_root: Path
    android_root: Path
    config_source: Path
    output: Path
    release_id: str
    artifacts: tuple[Path, ...] = ()
    strict_release: bool = False
    generated_at: datetime | None = None


def _is_reparse_point(path: Path) -> bool:
    result = path.is_symlink()
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return result or bool(attributes & reparse_flag)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _safe_relative_text(path: PurePosixPath) -> str:
    return path.as_posix()


def _forbidden_path_issue(relative: PurePosixPath) -> Issue | None:
    lowered_parts = [part.casefold() for part in relative.parts]
    for part in lowered_parts[:-1]:
        if (
            part in GLOBAL_PRUNED_DIR_NAMES
            or part.startswith(".codex")
            or part.startswith(".gradle")
        ):
            return Issue("FORBIDDEN_DIRECTORY", relative.as_posix())

    name = lowered_parts[-1]
    suffix = PurePosixPath(name).suffix.casefold()
    if name in FORBIDDEN_EXACT_NAMES or suffix in FORBIDDEN_SUFFIXES:
        return Issue("FORBIDDEN_FILE", relative.as_posix())
    if (
        "screenshot" in name
        or "screencap" in name
        or "\u622a\u56fe" in name
        or "\u62a5\u544a" in name
        or "\u7f13\u5b58" in name
    ):
        return Issue("FORBIDDEN_FILE", relative.as_posix())
    if (
        name.endswith("-report.json")
        or name.endswith("_report.json")
        or name.endswith("-metadata.json")
        or name.endswith("_metadata.json")
        or name.endswith(".jsonl")
    ):
        return Issue("FORBIDDEN_FILE", relative.as_posix())
    if (
        "private_key" in name
        or "private-key" in name
        or "signing_key" in name
        or "signing-key" in name
    ):
        return Issue("PRIVATE_KEY_FILE", relative.as_posix())
    return None


def _security_issues(path: Path, destination: PurePosixPath) -> list[Issue]:
    issues: list[Issue] = []
    relative_text = destination.as_posix()
    size = path.stat().st_size
    if size > MAX_GIT_FILE_BYTES:
        issues.append(Issue("GIT_FILE_OVER_50_MIB", relative_text))
        return issues

    forbidden = _forbidden_path_issue(destination)
    if forbidden is not None:
        issues.append(forbidden)
        return issues

    if path.suffix.casefold() not in TEXT_SUFFIXES and path.name not in {
        "COPYING",
        "LICENSE",
        "Makefile",
        "gradlew",
        "vectors",
    }:
        return issues

    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return issues

    checks = (
        ("SUSPECTED_PHONE_NUMBER", PHONE_RE),
        ("SUSPECTED_ACCOUNT_ID", ACCOUNT_IDENTITY_RE),
        ("SUSPECTED_ACCOUNT_ID", ACCOUNT_FIELD_RE),
        ("PRIVATE_KEY_CONTENT", PRIVATE_KEY_RE),
        ("SUSPECTED_SECRET", SECRET_ASSIGNMENT_RE),
        ("SUSPECTED_BEARER_TOKEN", BEARER_RE),
        ("SUSPECTED_ACCESS_TOKEN", KNOWN_TOKEN_RE),
        ("SUSPECTED_ACCESS_TOKEN", AWS_ACCESS_KEY_RE),
        ("CREDENTIAL_URL", CREDENTIAL_URL_RE),
        ("ABSOLUTE_LOCAL_PATH", WINDOWS_ABSOLUTE_PATH_RE),
        ("ABSOLUTE_LOCAL_PATH", UNC_PATH_RE),
        ("ABSOLUTE_LOCAL_PATH", POSIX_LOCAL_PATH_RE),
        ("ABSOLUTE_LOCAL_PATH", FILE_URL_RE),
    )
    for code, pattern in checks:
        if pattern.search(text):
            issues.append(Issue(code, relative_text))
    return issues


def _add_copy_item(
    items: dict[PurePosixPath, Path],
    source: Path,
    destination: PurePosixPath,
) -> None:
    if not source.exists():
        return
    if not source.is_file():
        raise TreeBuildError([Issue("ALLOWLIST_ENTRY_NOT_FILE", str(source.name))])
    if _is_reparse_point(source):
        raise TreeBuildError([Issue("REPARSE_POINT_REJECTED", destination.as_posix())])
    prior = items.get(destination)
    if prior is not None and prior.resolve() != source.resolve():
        raise TreeBuildError([Issue("DESTINATION_COLLISION", destination.as_posix())])
    items[destination] = source


def _walk_allowlisted_tree(
    *,
    source_root: Path,
    destination_root: PurePosixPath,
    vendor: bool = False,
    blocked_prefixes: Sequence[PurePosixPath] = (),
) -> list[CopyItem]:
    if not source_root.exists():
        return []
    if not source_root.is_dir() or _is_reparse_point(source_root):
        raise TreeBuildError(
            [Issue("ALLOWLIST_TREE_INVALID", destination_root.as_posix())]
        )

    result: list[CopyItem] = []
    for current, dir_names, file_names in os.walk(source_root, topdown=True):
        current_path = Path(current)
        relative_dir = current_path.relative_to(source_root)
        relative_dir_posix = PurePosixPath(*relative_dir.parts)

        kept_dirs: list[str] = []
        for name in sorted(dir_names):
            lowered = name.casefold()
            child_relative = relative_dir_posix / name
            if (
                lowered in GLOBAL_PRUNED_DIR_NAMES
                or lowered.startswith(".codex")
                or lowered.startswith(".gradle")
            ):
                continue
            if vendor and lowered in VENDOR_PRUNED_DIR_NAMES:
                continue
            if any(
                child_relative == prefix
                or child_relative.is_relative_to(prefix)
                for prefix in blocked_prefixes
            ):
                continue
            child_path = current_path / name
            if _is_reparse_point(child_path):
                raise TreeBuildError(
                    [
                        Issue(
                            "REPARSE_POINT_REJECTED",
                            (destination_root / child_relative).as_posix(),
                        )
                    ]
                )
            kept_dirs.append(name)
        dir_names[:] = kept_dirs

        for name in sorted(file_names):
            relative = relative_dir_posix / name
            if any(
                relative == prefix or relative.is_relative_to(prefix)
                for prefix in blocked_prefixes
            ):
                continue
            destination = destination_root / relative
            if _forbidden_path_issue(destination) is not None:
                continue
            source = current_path / name
            if _is_reparse_point(source):
                raise TreeBuildError(
                    [Issue("REPARSE_POINT_REJECTED", destination.as_posix())]
                )
            result.append(CopyItem(source=source, destination=destination))
    return result


def _collect_copy_items(pc_root: Path, android_root: Path) -> list[CopyItem]:
    items: dict[PurePosixPath, Path] = {}

    for name in PC_ROOT_FILES:
        _add_copy_item(items, pc_root / name, PurePosixPath("src", "pc", name))
    for name in PC_DATA_FILES:
        _add_copy_item(
            items,
            pc_root / "DatAnDict" / name,
            PurePosixPath("src", "pc", "DatAnDict", name),
        )
    for name in PC_PACKAGING_FILES:
        _add_copy_item(
            items,
            pc_root / "Packaging" / name,
            PurePosixPath("src", "pc", "Packaging", name),
        )
    for name in PC_TEST_FILES:
        _add_copy_item(
            items,
            pc_root / "Test" / name,
            PurePosixPath("src", "pc", "Test", name),
        )
    for item in _walk_allowlisted_tree(
        source_root=pc_root / "Docs",
        destination_root=PurePosixPath("src", "pc", "Docs"),
    ):
        _add_copy_item(items, item.source, item.destination)

    for name in ANDROID_ROOT_FILES:
        _add_copy_item(
            items,
            android_root / name,
            PurePosixPath("src", "android", name),
        )
    for name in ANDROID_APP_FILES:
        _add_copy_item(
            items,
            android_root / "app" / name,
            PurePosixPath("src", "android", "app", name),
        )

    android_trees = (
        ("app/src", False, (PurePosixPath("main", "jni", "tests"),)),
        ("conformance", False, ()),
        ("generated", False, ()),
        ("gradle", False, ()),
        ("tools", False, ()),
        ("ICONS_LICENSE", False, ()),
        ("submodules/nDPI/src/include", True, ()),
        ("submodules/nDPI/src/lib", True, ()),
        ("submodules/libpcap", True, ()),
        ("submodules/zdtun", True, ()),
        ("submodules/zstd/lib", True, ()),
        ("submodules/MaxMind-DB-Reader-java/src/main", True, ()),
    )
    for relative_text, vendor, blocked_prefixes in android_trees:
        relative = PurePosixPath(relative_text)
        source = android_root.joinpath(*relative.parts)
        destination = PurePosixPath("src", "android") / relative
        for item in _walk_allowlisted_tree(
            source_root=source,
            destination_root=destination,
            vendor=vendor,
            blocked_prefixes=blocked_prefixes,
        ):
            _add_copy_item(items, item.source, item.destination)

    vendor_license_files = (
        "submodules/nDPI/COPYING",
        "submodules/libpcap/LICENSE",
        "submodules/zdtun/COPYING",
        "submodules/zstd/COPYING",
        "submodules/zstd/LICENSE",
        "submodules/MaxMind-DB-Reader-java/LICENSE",
    )
    for relative_text in vendor_license_files:
        relative = PurePosixPath(relative_text)
        _add_copy_item(
            items,
            android_root.joinpath(*relative.parts),
            PurePosixPath("src", "android") / relative,
        )

    return [
        CopyItem(source=source, destination=destination)
        for destination, source in sorted(items.items(), key=lambda pair: pair[0])
    ]


def _read_config(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TreeBuildError([Issue("CONFIG_INVALID_JSON", path.name)]) from error
    if not isinstance(value, dict):
        raise TreeBuildError([Issue("CONFIG_NOT_OBJECT", path.name)])
    required = {
        "schema_version",
        "config_version",
        "config_id",
        "issued_at",
        "expires_at",
        "target_package",
        "content_sha256",
        "compatibility_profiles",
        "compact_catalog",
        "compact_registry",
        "pool_catalog",
        "signature",
    }
    if not required.issubset(value):
        raise TreeBuildError([Issue("CONFIG_MISSING_REQUIRED_FIELDS", path.name)])
    signature = value.get("signature")
    if not isinstance(signature, dict) or not {
        "algorithm",
        "key_id",
        "value",
    }.issubset(signature):
        raise TreeBuildError([Issue("CONFIG_SIGNATURE_METADATA_INVALID", path.name)])
    return value


def _artifact_media_type(path: Path) -> str:
    suffix = path.suffix.casefold()
    if suffix == ".apk":
        return "application/vnd.android.package-archive"
    if suffix == ".exe":
        return "application/vnd.microsoft.portable-executable"
    raise TreeBuildError([Issue("UNSUPPORTED_RELEASE_ARTIFACT", path.name)])


def _collect_artifacts(paths: Sequence[Path]) -> list[ArtifactRecord]:
    records: list[ArtifactRecord] = []
    names: set[str] = set()
    for input_path in paths:
        path = input_path.resolve()
        if not path.is_file() or _is_reparse_point(path):
            raise TreeBuildError([Issue("RELEASE_ARTIFACT_INVALID", input_path.name)])
        name = path.name
        if (
            not name
            or name in {".", ".."}
            or any(ord(char) < 32 for char in name)
            or "/" in name
            or "\\" in name
        ):
            raise TreeBuildError([Issue("RELEASE_ARTIFACT_NAME_INVALID", name)])
        if name.casefold() in names:
            raise TreeBuildError([Issue("RELEASE_ARTIFACT_NAME_DUPLICATE", name)])
        names.add(name.casefold())
        size = path.stat().st_size
        if size <= 0:
            raise TreeBuildError([Issue("RELEASE_ARTIFACT_EMPTY", name)])
        if size > MAX_RELEASE_ATTACHMENT_BYTES:
            raise TreeBuildError([Issue("RELEASE_ATTACHMENT_OVER_100_MIB", name)])
        records.append(
            ArtifactRecord(
                path=path,
                name=name,
                size=size,
                sha256=_sha256_file(path),
                media_type=_artifact_media_type(path),
            )
        )
    return sorted(records, key=lambda item: item.name.casefold())


def _apk_has_debug_certificate(path: Path) -> bool:
    if "debug" in path.name.casefold():
        return True
    try:
        with zipfile.ZipFile(path) as archive:
            certificate_names = [
                name
                for name in archive.namelist()
                if name.upper().startswith("META-INF/")
                and name.upper().endswith((".RSA", ".DSA", ".EC"))
            ]
            return any(
                b"Android Debug" in archive.read(name)
                for name in certificate_names
            )
    except (OSError, zipfile.BadZipFile, KeyError):
        return True


def _pe_has_certificate_table(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            file_size = path.stat().st_size
            header = stream.read(64)
            if len(header) < 64 or header[:2] != b"MZ":
                return False
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            stream.seek(pe_offset)
            pe_header = stream.read(24)
            if len(pe_header) < 24 or pe_header[:4] != b"PE\0\0":
                return False
            optional_size = struct.unpack_from("<H", pe_header, 20)[0]
            optional = stream.read(optional_size)
            if len(optional) != optional_size or len(optional) < 120:
                return False
            magic = struct.unpack_from("<H", optional, 0)[0]
            if magic == 0x10B:
                directory_offset = 96
            elif magic == 0x20B:
                directory_offset = 112
            else:
                return False
            certificate_offset = directory_offset + (4 * 8)
            if len(optional) < certificate_offset + 8:
                return False
            address, size = struct.unpack_from("<II", optional, certificate_offset)
            if address <= 0 or size < 8 or address + size > file_size:
                return False
            stream.seek(address)
            certificate_header = stream.read(8)
            if len(certificate_header) != 8:
                return False
            length, revision, certificate_type = struct.unpack(
                "<IHH", certificate_header
            )
            return (
                8 <= length <= size
                and revision in {0x0100, 0x0200}
                and certificate_type == 0x0002
            )
    except (OSError, struct.error):
        return False


def _read_text_if_present(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _strict_release_issues(
    *,
    pc_root: Path,
    android_root: Path,
    config_source: Path,
    config: dict[str, object],
    artifacts: Sequence[ArtifactRecord],
    generated_at: datetime,
) -> list[Issue]:
    issues: list[Issue] = []

    pc_license = _read_text_if_present(pc_root / "LICENSE").casefold()
    pc_notices = _read_text_if_present(
        pc_root / "THIRD_PARTY_NOTICES.md"
    ).casefold()
    requirements = _read_text_if_present(
        pc_root / "YKARequirementsLock.txt"
    ).casefold()
    if not pc_notices:
        issues.append(Issue("PC_THIRD_PARTY_NOTICES_MISSING", "src/pc"))
    if (
        "affero general public license" in pc_license
        and "scapy" in requirements
        and "scapy" in pc_notices
        and "gpl-2.0-only" in pc_notices
    ):
        issues.append(Issue("PC_AGPL_SCAPY_GPL2_ONLY_CONFLICT", "src/pc"))

    android_notices = android_root / "THIRD_PARTY_NOTICES.md"
    if not android_notices.is_file():
        issues.append(
            Issue("ANDROID_THIRD_PARTY_NOTICES_MISSING", "src/android")
        )

    copying = _read_text_if_present(android_root / "COPYING").casefold()
    agpl_detected = False
    java_root = android_root / "app" / "src" / "main"
    if java_root.is_dir():
        for path in java_root.rglob("*"):
            if (
                path.is_file()
                and path.suffix.casefold() in {".java", ".xml"}
                and "affero general public license"
                in _read_text_if_present(path).casefold()
            ):
                agpl_detected = True
                break
    license_scope = _read_text_if_present(
        android_root / "LICENSE_SCOPE.md"
    ).casefold()
    has_agpl_text = (
        android_root / "LICENSES" / "AGPL-3.0-only.txt"
    ).is_file()
    has_documented_mixed_scope = (
        "gpl-3.0" in license_scope
        and "agpl-3.0" in license_scope
        and has_agpl_text
    )
    if (
        "gnu general public license" in copying
        and agpl_detected
        and not has_documented_mixed_scope
    ):
        issues.append(
            Issue("ANDROID_LICENSE_DECLARATIONS_MIXED", "src/android")
        )

    icon_license_root = android_root / "ICONS_LICENSE"
    if icon_license_root.is_dir():
        icon_text = "\n".join(
            _read_text_if_present(path)
            for path in icon_license_root.rglob("*")
            if path.is_file()
        ).casefold()
        if "noncommercial" in icon_text or "freepik" in icon_text:
            issues.append(
                Issue("ANDROID_NONCOMMERCIAL_ICON_ASSET", "src/android")
            )

    raw_root = android_root / "app" / "src" / "main" / "res" / "raw"
    audio_files = (
        [
            path
            for path in raw_root.iterdir()
            if path.is_file()
            and path.suffix.casefold()
            in {".aac", ".flac", ".m4a", ".mp3", ".ogg", ".wav"}
        ]
        if raw_root.is_dir()
        else []
    )
    if audio_files:
        audio_notice = android_root / "AUDIO_LICENSES.md"
        notice_text = _read_text_if_present(audio_notice).casefold()
        undocumented = [
            path.name
            for path in audio_files
            if path.name.casefold() not in notice_text
        ]
        if undocumented:
            issues.append(
                Issue("ANDROID_AUDIO_LICENSE_MISSING", "src/android")
            )

    suffixes = {record.path.suffix.casefold() for record in artifacts}
    if ".apk" not in suffixes or ".exe" not in suffixes:
        issues.append(Issue("STRICT_RELEASE_ARTIFACT_SET_INCOMPLETE", "release"))
    for record in artifacts:
        suffix = record.path.suffix.casefold()
        if suffix == ".apk" and _apk_has_debug_certificate(record.path):
            issues.append(Issue("ANDROID_DEBUG_SIGNING_BLOCKED", record.name))
        if suffix == ".exe" and not _pe_has_certificate_table(record.path):
            issues.append(Issue("WINDOWS_AUTHENTICODE_MISSING", record.name))

    builtin = pc_root / "DatAnDict" / "YKAConfigBuiltin.json"
    android_builtin = (
        android_root
        / "app"
        / "src"
        / "main"
        / "assets"
        / "yka"
        / "YKAConfigBuiltin.json"
    )
    if not builtin.is_file() or builtin.read_bytes() != config_source.read_bytes():
        issues.append(Issue("PC_BUILTIN_CONFIG_MISMATCH", "src/pc"))
    if (
        not android_builtin.is_file()
        or android_builtin.read_bytes() != config_source.read_bytes()
    ):
        issues.append(Issue("ANDROID_BUILTIN_CONFIG_MISMATCH", "src/android"))

    expires_at = config.get("expires_at")
    if not isinstance(expires_at, str):
        issues.append(Issue("CONFIG_EXPIRY_MISSING", "config/latest.json"))
    else:
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if expiry.tzinfo is None or expiry.astimezone(timezone.utc) <= generated_at:
                issues.append(Issue("CONFIG_EXPIRED", "config/latest.json"))
        except ValueError:
            issues.append(Issue("CONFIG_EXPIRY_INVALID", "config/latest.json"))
    return issues


def _validate_required_sources(pc_root: Path, android_root: Path) -> list[Issue]:
    required = (
        (pc_root / "LICENSE", "src/pc/LICENSE"),
        (pc_root / "README.md", "src/pc/README.md"),
        (pc_root / "YKAApp.py", "src/pc/YKAApp.py"),
        (android_root / "COPYING", "src/android/COPYING"),
        (android_root / "app" / "build.gradle", "src/android/app/build.gradle"),
        (
            android_root / "app" / "src" / "main" / "AndroidManifest.xml",
            "src/android/app/src/main/AndroidManifest.xml",
        ),
    )
    return [
        Issue("REQUIRED_SOURCE_MISSING", destination)
        for source, destination in required
        if not source.is_file()
    ]


def _validate_options(options: BuildOptions) -> tuple[Path, Path, Path, Path]:
    pc_root = options.pc_root.resolve()
    android_root = options.android_root.resolve()
    config_source = options.config_source.resolve()
    output = options.output.resolve()

    issues: list[Issue] = []
    if not pc_root.is_dir():
        issues.append(Issue("PC_ROOT_INVALID", "src/pc"))
    if not android_root.is_dir():
        issues.append(Issue("ANDROID_ROOT_INVALID", "src/android"))
    if not config_source.is_file():
        issues.append(Issue("CONFIG_SOURCE_INVALID", "config/latest.json"))
    if output.parent == output or not output.parent.is_dir():
        issues.append(Issue("OUTPUT_PARENT_INVALID", output.name))
    if output.exists():
        if not output.is_dir() or _is_reparse_point(output):
            issues.append(Issue("OUTPUT_NOT_EMPTY_DIRECTORY", output.name))
        elif any(output.iterdir()):
            issues.append(Issue("OUTPUT_NOT_EMPTY_DIRECTORY", output.name))
    for root in (pc_root, android_root):
        if output == root or _is_relative_to(output, root):
            issues.append(Issue("OUTPUT_INSIDE_SOURCE_TREE", output.name))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", options.release_id):
        issues.append(Issue("RELEASE_ID_INVALID", "release/index.json"))
    if issues:
        raise TreeBuildError(issues)
    return pc_root, android_root, config_source, output


def _normalized_generated_at(value: datetime | None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None:
        raise TreeBuildError([Issue("GENERATED_AT_REQUIRES_TIMEZONE")])
    return result.astimezone(timezone.utc).replace(microsecond=0)


def _utc_text(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _validate_staged_tree(stage: Path) -> None:
    issues: list[Issue] = []
    for path in sorted(stage.rglob("*")):
        if path.is_dir():
            if _is_reparse_point(path):
                issues.append(
                    Issue("REPARSE_POINT_REJECTED", path.relative_to(stage).as_posix())
                )
            continue
        relative = PurePosixPath(*path.relative_to(stage).parts)
        issues.extend(_security_issues(path, relative))

    expected = {
        PurePosixPath("src", "pc"),
        PurePosixPath("src", "android"),
        PurePosixPath("config", "latest.json"),
        PurePosixPath("release", "index.json"),
        PurePosixPath("release", "SHA256SUMS.txt"),
    }
    for relative in expected:
        target = stage.joinpath(*relative.parts)
        if not target.exists():
            issues.append(Issue("OUTPUT_ENTRY_MISSING", relative.as_posix()))

    release_files = {
        path.relative_to(stage / "release").as_posix()
        for path in (stage / "release").rglob("*")
        if path.is_file()
    }
    if release_files != {"index.json", "SHA256SUMS.txt"}:
        issues.append(Issue("RELEASE_CONTAINS_UNEXPECTED_FILES", "release"))
    if issues:
        raise TreeBuildError(issues)


def build_tree(options: BuildOptions) -> dict[str, object]:
    pc_root, android_root, config_source, output = _validate_options(options)
    generated_at = _normalized_generated_at(options.generated_at)
    config = _read_config(config_source)
    artifacts = _collect_artifacts(options.artifacts)
    copy_items = _collect_copy_items(pc_root, android_root)

    issues = _validate_required_sources(pc_root, android_root)
    for item in copy_items:
        issues.extend(_security_issues(item.source, item.destination))
    config_destination = PurePosixPath("config", "latest.json")
    issues.extend(_security_issues(config_source, config_destination))
    if options.strict_release:
        issues.extend(
            _strict_release_issues(
                pc_root=pc_root,
                android_root=android_root,
                config_source=config_source,
                config=config,
                artifacts=artifacts,
                generated_at=generated_at,
            )
        )
    if issues:
        raise TreeBuildError(issues)

    stage = Path(
        tempfile.mkdtemp(
            prefix=f".{output.name}.staging-",
            dir=str(output.parent),
        )
    )
    completed = False
    try:
        for item in copy_items:
            destination = stage.joinpath(*item.destination.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item.source, destination)

        config_target = stage / "config" / "latest.json"
        config_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(config_source, config_target)
        config_sha256 = _sha256_file(config_target)

        index = {
            "schema_version": 1,
            "release_id": options.release_id,
            "generated_at_utc": _utc_text(generated_at),
            "strict_release": options.strict_release,
            "source_layout": {
                "pc": "src/pc",
                "android": "src/android",
            },
            "config": {
                "path": "config/latest.json",
                "config_id": config.get("config_id"),
                "config_version": config.get("config_version"),
                "bytes": config_target.stat().st_size,
                "sha256": config_sha256,
            },
            "artifacts": [
                {
                    "name": record.name,
                    "bytes": record.size,
                    "sha256": record.sha256,
                    "media_type": record.media_type,
                    "delivery": "gitee-release-attachment",
                }
                for record in artifacts
            ],
        }
        _write_json(stage / "release" / "index.json", index)
        checksums = "".join(
            f"{record.sha256}  {record.name}\n" for record in artifacts
        )
        (stage / "release" / "SHA256SUMS.txt").write_text(
            checksums,
            encoding="utf-8",
            newline="\n",
        )

        _validate_staged_tree(stage)
        if output.exists():
            output.rmdir()
        os.replace(stage, output)
        completed = True
        return {
            "output": str(output),
            "release_id": options.release_id,
            "strict_release": options.strict_release,
            "source_files": len(copy_items),
            "artifact_count": len(artifacts),
            "config_sha256": config_sha256,
        }
    finally:
        if not completed and stage.exists():
            shutil.rmtree(stage)


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise argparse.ArgumentTypeError("invalid timestamp") from error
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("timestamp must include a timezone")
    return parsed


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    workspace_root = project_root.parent
    parser = argparse.ArgumentParser(
        description="Build a sanitized, source-only Gitee publication tree."
    )
    parser.add_argument("--pc-root", type=Path, default=project_root)
    parser.add_argument(
        "--android-root",
        type=Path,
        default=workspace_root / "YKAPhone-ver1.0-Preview",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=project_root / "DatAnDict" / "YKAConfigBuiltin.json",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--artifact", type=Path, action="append", default=[])
    parser.add_argument("--strict-release", action="store_true")
    parser.add_argument("--generated-at", type=_parse_timestamp)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = build_tree(
            BuildOptions(
                pc_root=args.pc_root,
                android_root=args.android_root,
                config_source=args.config,
                output=args.output,
                release_id=args.release_id,
                artifacts=tuple(args.artifact),
                strict_release=args.strict_release,
                generated_at=args.generated_at,
            )
        )
    except TreeBuildError as error:
        print(
            json.dumps(
                {
                    "ok": False,
                    "issues": [
                        {"code": issue.code, "path": issue.path}
                        for issue in error.issues
                    ],
                },
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {"ok": True, **result},
            ensure_ascii=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
