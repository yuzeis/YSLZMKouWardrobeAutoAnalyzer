from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
import threading
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from YKACore import DATA_ROOT, PROJECT_ROOT, append_jsonl, atomic_write_json, now_iso


SCHEMA_VERSION = 1
SHELL_VERSION = 1
TARGET_PACKAGE = "com.zulong.yslzm"
SIGNATURE_ALGORITHM = "RSA-3072-PKCS1-v1_5-SHA256"
DEFAULT_REMOTE_URL = "https://gitee.com/yuzeis/yka/raw/main/config/latest.json"
CONFIG_URL_ENV = "YKA_CONFIG_URL"
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_STATE_BYTES = 64 * 1024
NETWORK_TIMEOUT_SECONDS = 8.0
FUTURE_CLOCK_TOLERANCE = timedelta(minutes=5)
SECTION_NAMES = (
    "compatibility_profiles",
    "compact_catalog",
    "compact_registry",
    "pool_catalog",
)
BUSINESS_OPCODE_NAMES = (
    "fashion_info_ack",
    "fashion_info",
    "active_fashion",
    "fashion_expire",
    "fashion_renew",
    "photo_info",
    "diy_fashion_data",
    "fashion_obtain_suit",
    "luckydraw_operate_re",
    "photo_operate_re",
)
ROOT_KEYS = frozenset(
    {
        "schema_version",
        "config_version",
        "config_id",
        "issued_at",
        "expires_at",
        "min_shell_version",
        "target_package",
        "game_version_range",
        "content_sha256",
        *SECTION_NAMES,
        "signature",
    }
)
SIGNATURE_KEYS = frozenset({"algorithm", "key_id", "value"})
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


class ConfigError(ValueError):
    pass


class ConfigValidationError(ConfigError):
    pass


class ConfigRollbackError(ConfigError):
    pass


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ConfigValidationError(f"configuration is not canonical JSON: {error}") from error


def _snapshot_json(value: dict[str, Any]) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ConfigValidationError(f"snapshot section is invalid: {error}") from error


def _reject_constant(value: str) -> Any:
    raise ConfigValidationError(f"non-finite JSON number is not allowed: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_json(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ConfigValidationError(
            f"configuration exceeds {MAX_BUNDLE_BYTES} byte limit"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ConfigValidationError("configuration is not UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as error:
        raise ConfigValidationError(f"configuration JSON is invalid: {error}") from error
    if not isinstance(value, dict):
        raise ConfigValidationError("configuration root must be an object")
    return value


def _read_limited(path: Path) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ConfigValidationError(f"cannot stat configuration {path}: {error}") from error
    if size > MAX_BUNDLE_BYTES:
        raise ConfigValidationError(
            f"configuration exceeds {MAX_BUNDLE_BYTES} byte limit"
        )
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_BUNDLE_BYTES + 1)
    except OSError as error:
        raise ConfigValidationError(f"cannot read configuration {path}: {error}") from error
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ConfigValidationError(
            f"configuration exceeds {MAX_BUNDLE_BYTES} byte limit"
        )
    return raw


def _parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ConfigValidationError(f"{field} must be a UTC timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise ConfigValidationError(f"{field} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ConfigValidationError(f"{field} must use UTC")
    return parsed.astimezone(timezone.utc)


def _positive_int(value: Any, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise ConfigValidationError(f"{field} must be a positive integer")
    return value


def _integer_set(value: Any, field: str, maximum: int) -> frozenset[int]:
    if not isinstance(value, list) or not value:
        raise ConfigValidationError(f"{field} must be a non-empty integer list")
    parsed = frozenset(item for item in value if type(item) is int)
    if (
        len(parsed) != len(value)
        or any(item <= 0 or item > maximum for item in parsed)
    ):
        raise ConfigValidationError(f"{field} contains an invalid integer")
    return parsed


@dataclass(frozen=True)
class ConfigSnapshot:
    config_version: int
    config_id: str
    source: str
    bundle_sha256: str
    issued_at: str
    expires_at: str
    _compatibility_profiles_json: str
    _compact_catalog_json: str
    _compact_registry_json: str
    _pool_catalog_json: str

    @staticmethod
    def _fresh(value: str) -> dict[str, Any]:
        decoded = json.loads(value)
        if not isinstance(decoded, dict):
            raise ConfigValidationError("snapshot section is not an object")
        return decoded

    @property
    def compatibility_profiles(self) -> dict[str, Any]:
        return self._fresh(self._compatibility_profiles_json)

    @property
    def compact_catalog(self) -> dict[str, Any]:
        return self._fresh(self._compact_catalog_json)

    @property
    def compact_registry(self) -> dict[str, Any]:
        return self._fresh(self._compact_registry_json)

    @property
    def pool_catalog(self) -> dict[str, Any]:
        return self._fresh(self._pool_catalog_json)

    def audit_metadata(self) -> dict[str, Any]:
        return {
            "config_id": self.config_id,
            "config_version": self.config_version,
            "source": self.source,
            "bundle_sha256": self.bundle_sha256,
        }


@dataclass(frozen=True)
class FetchResult:
    body: bytes | None
    etag: str = ""
    not_modified: bool = False


def _valid_etag(value: Any) -> str:
    if (
        isinstance(value, str)
        and len(value) <= 512
        and re.fullmatch(r'(?:W/)?"[\x21\x23-\x7e]*"', value) is not None
    ):
        return value
    return ""


def _is_strict_https_url(url: str, *, hostname: str | None = None) -> bool:
    try:
        parsed = urlsplit(url)
        explicit_port = parsed.port is not None
    except ValueError:
        return False
    authority = parsed.netloc.rsplit("@", 1)[-1]
    return (
        parsed.scheme.lower() == "https"
        and bool(parsed.hostname)
        and (hostname is None or parsed.hostname == hostname)
        and parsed.username is None
        and parsed.password is None
        and not explicit_port
        and ":" not in authority
        and not parsed.fragment
    )


class _RestrictedRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        allowed = (
            _is_strict_https_url(req.full_url, hostname="gitee.com")
            and _is_strict_https_url(
                newurl,
                hostname="raw.giteeusercontent.com",
            )
        )
        if not allowed:
            raise HTTPError(
                req.full_url,
                code,
                "configuration redirect is not allowed",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_fetch(url: str, etag: str = "") -> FetchResult:
    if not _is_strict_https_url(url):
        raise ConfigValidationError(
            "configuration URL must use strict HTTPS without userinfo or ports"
        )
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "YKA-PC-Config/1",
    }
    conditional_etag = _valid_etag(etag)
    if conditional_etag:
        request_headers["If-None-Match"] = conditional_etag
    request = Request(
        url,
        headers=request_headers,
    )
    opener = build_opener(_RestrictedRedirectHandler())
    try:
        response_context = opener.open(request, timeout=NETWORK_TIMEOUT_SECONDS)
    except HTTPError as error:
        if error.code == 304:
            response_etag = _valid_etag(
                error.headers.get("ETag")
                if error.headers is not None
                else None
            )
            error.close()
            if conditional_etag and response_etag == conditional_etag:
                return FetchResult(
                    body=None,
                    etag=response_etag,
                    not_modified=True,
                )
            raise ConfigValidationError(
                "HTTP 304 response ETag is missing or does not match request"
            ) from error
        raise
    with response_context as response:
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = -1
            if declared_length > MAX_BUNDLE_BYTES:
                raise ConfigValidationError(
                    f"remote configuration exceeds {MAX_BUNDLE_BYTES} byte limit"
                )
        raw = response.read(MAX_BUNDLE_BYTES + 1)
        response_etag = _valid_etag(response.headers.get("ETag"))
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ConfigValidationError(
            f"remote configuration exceeds {MAX_BUNDLE_BYTES} byte limit"
        )
    return FetchResult(body=raw, etag=response_etag)


class ConfigManager:
    def __init__(
        self,
        *,
        data_root: Path | None = None,
        builtin_path: Path | None = None,
        trust_path: Path | None = None,
        remote_url: str | None = None,
        now: Callable[[], datetime] | None = None,
        fetcher: Callable[[str], bytes | FetchResult] | None = None,
    ) -> None:
        resource_root = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))
        self.config_root = (data_root or (DATA_ROOT / "config")).resolve()
        self.builtin_path = (
            builtin_path
            or resource_root / "DatAnDict" / "YKAConfigBuiltin.json"
        ).resolve()
        self.trust_path = (
            trust_path
            or resource_root / "DatAnDict" / "YKAConfigTrust.json"
        ).resolve()
        self.current_path = self.config_root / "current.json"
        self.previous_path = self.config_root / "previous.json"
        self.state_path = self.config_root / "state.json"
        self.events_path = self.config_root / "events.jsonl"
        configured_url = os.environ.get(CONFIG_URL_ENV, "").strip()
        self.remote_url = (
            remote_url if remote_url is not None else configured_url or DEFAULT_REMOTE_URL
        )
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._fetcher = fetcher
        self._lock = threading.RLock()
        self._background_lock = threading.Lock()
        self._background_thread: threading.Thread | None = None
        self._trust_keys: dict[str, dict[str, Any]] | None = None

    def _log(self, event: str, **details: Any) -> None:
        try:
            append_jsonl(
                self.events_path,
                {
                    "timestamp": now_iso(),
                    "event": event,
                    **details,
                },
            )
        except OSError:
            pass

    def _load_trust_keys(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            if self._trust_keys is not None:
                return self._trust_keys
            trust = _decode_json(_read_limited(self.trust_path))
            if trust.get("schema_version") != 1:
                raise ConfigValidationError("unsupported trust store schema")
            raw_keys = trust.get("keys")
            if not isinstance(raw_keys, list) or not raw_keys:
                raise ConfigValidationError("trust store has no keys")
            parsed: dict[str, dict[str, Any]] = {}
            for entry in raw_keys:
                if not isinstance(entry, dict):
                    raise ConfigValidationError("trust store key is invalid")
                key_id = entry.get("key_id")
                algorithm = entry.get("algorithm")
                modulus_hex = entry.get("modulus_hex")
                exponent = entry.get("exponent")
                if (
                    not isinstance(key_id, str)
                    or not key_id
                    or key_id in parsed
                    or algorithm != SIGNATURE_ALGORITHM
                    or not isinstance(modulus_hex, str)
                    or re.fullmatch(r"[0-9a-fA-F]{768}", modulus_hex) is None
                    or exponent != 65537
                ):
                    raise ConfigValidationError("trust store key metadata is invalid")
                parsed[key_id] = {
                    "algorithm": algorithm,
                    "modulus": int(modulus_hex, 16),
                    "exponent": exponent,
                }
            self._trust_keys = parsed
            return parsed

    def _verify_signature(self, document: dict[str, Any]) -> None:
        signature = document.get("signature")
        if (
            not isinstance(signature, dict)
            or frozenset(signature) != SIGNATURE_KEYS
        ):
            raise ConfigValidationError("signature metadata is invalid")
        algorithm = signature.get("algorithm")
        key_id = signature.get("key_id")
        encoded_value = signature.get("value")
        if (
            algorithm != SIGNATURE_ALGORITHM
            or not isinstance(key_id, str)
            or not isinstance(encoded_value, str)
        ):
            raise ConfigValidationError("signature metadata is unsupported")
        trusted_key = self._load_trust_keys().get(key_id)
        if trusted_key is None or trusted_key["algorithm"] != algorithm:
            raise ConfigValidationError("signature key is not trusted")
        try:
            signature_bytes = base64.b64decode(encoded_value, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ConfigValidationError("signature value is invalid") from error
        if len(signature_bytes) != 384:
            raise ConfigValidationError("signature length is invalid")

        payload = dict(document)
        payload.pop("signature", None)
        digest = hashlib.sha256(_canonical_bytes(payload)).digest()
        expected_digest_info = SHA256_DIGEST_INFO_PREFIX + digest
        modulus = int(trusted_key["modulus"])
        signature_integer = int.from_bytes(signature_bytes, "big")
        if signature_integer >= modulus:
            raise ConfigValidationError("signature value is outside RSA modulus")
        decoded = pow(
            signature_integer,
            int(trusted_key["exponent"]),
            modulus,
        ).to_bytes(384, "big")
        separator = decoded.find(b"\x00", 2)
        if (
            not decoded.startswith(b"\x00\x01")
            or separator < 10
            or decoded[2:separator] != b"\xff" * (separator - 2)
            or not hmac.compare_digest(
                decoded[separator + 1 :],
                expected_digest_info,
            )
        ):
            raise ConfigValidationError("configuration signature verification failed")

    def _validate_sections(self, document: dict[str, Any]) -> None:
        expected_hashes = document.get("content_sha256")
        if (
            not isinstance(expected_hashes, dict)
            or frozenset(expected_hashes) != frozenset(SECTION_NAMES)
        ):
            raise ConfigValidationError("section hash registry is invalid")
        sections: dict[str, dict[str, Any]] = {}
        for name in SECTION_NAMES:
            section = document.get(name)
            expected = expected_hashes.get(name)
            if (
                not isinstance(section, dict)
                or not isinstance(expected, str)
                or re.fullmatch(r"[0-9a-fA-F]{64}", expected) is None
            ):
                raise ConfigValidationError(f"{name} section metadata is invalid")
            actual = hashlib.sha256(_canonical_bytes(section)).hexdigest()
            if not hmac.compare_digest(actual.lower(), expected.lower()):
                raise ConfigValidationError(f"{name} section hash does not match")
            sections[name] = section

        profiles = sections["compatibility_profiles"]
        compact = sections["compact_catalog"]
        registry = sections["compact_registry"]
        pool = sections["pool_catalog"]
        if profiles.get("schema_version") != 1:
            raise ConfigValidationError("unsupported compatibility profile schema")
        if compact.get("schema_version") != 1:
            raise ConfigValidationError("unsupported compact catalog schema")
        if registry.get("schema_version") != 1:
            raise ConfigValidationError("unsupported compact registry schema")
        if pool.get("schema_version") != 5:
            raise ConfigValidationError("unsupported pool catalog schema")

        active_id = profiles.get("active_profile_id")
        profile_entries = profiles.get("profiles")
        if not isinstance(profile_entries, list):
            raise ConfigValidationError("compatibility profile registry is invalid")
        active = next(
            (
                entry
                for entry in profile_entries
                if isinstance(entry, dict)
                and entry.get("profile_id") == active_id
            ),
            None,
        )
        if active is None:
            raise ConfigValidationError("active compatibility profile is missing")
        compact_id = compact.get("catalog_id")
        if active.get("catalog_bundle_id") != compact_id:
            raise ConfigValidationError("profile and compact catalog are not bound")
        package_names = active.get("package_names")
        if (
            not isinstance(package_names, list)
            or TARGET_PACKAGE not in package_names
        ):
            raise ConfigValidationError("active profile targets another package")
        if (
            active.get("parser_version") != 1
            or active.get("transport") != "compact-mppc-v1"
            or active.get("business_schema_id") != "yslzm-business-v1"
        ):
            raise ConfigValidationError("active profile requires an unsupported parser")
        _integer_set(active.get("service_ports"), "service_ports", 65535)
        protocol_signature = active.get("protocol_signature")
        if not isinstance(protocol_signature, dict):
            raise ConfigValidationError("compatibility protocol signature is missing")
        server_control_sets = tuple(
            _integer_set(
                protocol_signature.get(name),
                f"protocol_signature.{name}",
                0xFFFFFFFF,
            )
            for name in (
                "server_handshake_type_ids",
                "server_business_wrapper_type_ids",
                "key_exchange_type_ids",
            )
        )
        _integer_set(
            protocol_signature.get("client_authentication_type_ids"),
            "protocol_signature.client_authentication_type_ids",
            0xFFFFFFFF,
        )
        if any(
            left & right
            for index, left in enumerate(server_control_sets)
            for right in server_control_sets[index + 1 :]
        ):
            raise ConfigValidationError("server protocol type ids overlap")
        business_opcodes = active.get("business_opcodes")
        if not isinstance(business_opcodes, dict):
            raise ConfigValidationError("compatibility business opcodes are missing")
        opcode_owners: dict[int, str] = {}
        for name in BUSINESS_OPCODE_NAMES:
            for opcode in _integer_set(
                business_opcodes.get(name),
                f"business_opcodes.{name}",
                0xFFFFFFFF,
            ):
                if opcode in opcode_owners:
                    raise ConfigValidationError(
                        f"business opcode {opcode} overlaps "
                        f"{opcode_owners[opcode]} and {name}"
                    )
                opcode_owners[opcode] = name
        registry_catalogs = registry.get("catalogs")
        if (
            not isinstance(registry_catalogs, dict)
            or not isinstance(compact_id, str)
            or registry_catalogs.get(compact_id) != compact.get("content_sha256")
        ):
            raise ConfigValidationError("compact registry and catalog are not bound")
        compact_content_hash = compact.get("content_sha256")
        compact_hash_source = dict(compact)
        compact_hash_source["content_sha256"] = ""
        if (
            not isinstance(compact_content_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", compact_content_hash) is None
            or hashlib.sha256(
                _snapshot_json(compact_hash_source).encode("utf-8")
            ).hexdigest()
            != compact_content_hash
        ):
            raise ConfigValidationError("compact catalog content hash does not match")

        ordinary = compact.get("ordinary")
        background = compact.get("background")
        pools = pool.get("pools")
        if (
            not isinstance(ordinary, list)
            or not isinstance(background, list)
            or not isinstance(pools, list)
        ):
            raise ConfigValidationError("catalog pool lists are invalid")
        compact_keys = [
            entry.get("key") if isinstance(entry, dict) else None
            for entry in [*ordinary, *background]
        ]
        pool_keys = [
            entry.get("key") if isinstance(entry, dict) else None for entry in pools
        ]
        if (
            any(not isinstance(key, str) or not key for key in compact_keys)
            or any(not isinstance(key, str) or not key for key in pool_keys)
            or compact_keys != pool_keys
            or len(pool_keys) != len(set(pool_keys))
        ):
            raise ConfigValidationError("pool key order does not match compact catalog")
        if pool.get("pool_count") != len(pools):
            raise ConfigValidationError("pool catalog count does not match pools")
        pool_counts = pool.get("pool_counts")
        if (
            not isinstance(pool_counts, dict)
            or pool_counts.get("total") != len(pools)
        ):
            raise ConfigValidationError("pool catalog total does not match pools")
        try:
            from YKACompactCodec import load_catalog
            from YKAWechatImport import load_pool_catalog

            load_catalog(compact, registry)
            load_pool_catalog(pool)
        except (ImportError, OSError, TypeError, ValueError) as error:
            raise ConfigValidationError(
                f"configuration consumer validation failed: {error}"
            ) from error

    def validate_bytes(
        self,
        raw: bytes,
        *,
        source: str,
        enforce_expiry: bool,
        enforce_future_time: bool = True,
    ) -> ConfigSnapshot:
        document = _decode_json(raw)
        if frozenset(document) != ROOT_KEYS:
            raise ConfigValidationError("configuration root fields do not match schema")
        if document.get("schema_version") != SCHEMA_VERSION:
            raise ConfigValidationError("unsupported configuration schema")
        config_version = _positive_int(
            document.get("config_version"),
            "config_version",
        )
        config_id = document.get("config_id")
        if (
            not isinstance(config_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", config_id) is None
        ):
            raise ConfigValidationError("config_id is invalid")
        if document.get("target_package") != TARGET_PACKAGE:
            raise ConfigValidationError("configuration targets another package")
        minimum_shell = _positive_int(
            document.get("min_shell_version"),
            "min_shell_version",
        )
        if minimum_shell > SHELL_VERSION:
            raise ConfigValidationError("configuration requires a newer shell")
        game_range = document.get("game_version_range")
        if not isinstance(game_range, dict) or frozenset(game_range) != {"min", "max"}:
            raise ConfigValidationError("game version range is invalid")
        minimum_game = _positive_int(game_range.get("min"), "game_version_range.min")
        maximum_game = _positive_int(game_range.get("max"), "game_version_range.max")
        if minimum_game > maximum_game:
            raise ConfigValidationError("game version range is reversed")

        issued_at = _parse_utc(document.get("issued_at"), "issued_at")
        expires_at = _parse_utc(document.get("expires_at"), "expires_at")
        now = self._now().astimezone(timezone.utc)
        if expires_at <= issued_at:
            raise ConfigValidationError("configuration expiry precedes issue time")
        if enforce_future_time and issued_at > now + FUTURE_CLOCK_TOLERANCE:
            raise ConfigValidationError("configuration issue time is in the future")
        if enforce_expiry and expires_at <= now:
            raise ConfigValidationError("configuration is expired")

        self._verify_signature(document)
        self._validate_sections(document)
        bundle_sha256 = hashlib.sha256(_canonical_bytes(document)).hexdigest().upper()
        return ConfigSnapshot(
            config_version=config_version,
            config_id=config_id,
            source=source,
            bundle_sha256=bundle_sha256,
            issued_at=str(document["issued_at"]),
            expires_at=str(document["expires_at"]),
            _compatibility_profiles_json=_snapshot_json(
                document["compatibility_profiles"]
            ),
            _compact_catalog_json=_snapshot_json(document["compact_catalog"]),
            _compact_registry_json=_snapshot_json(document["compact_registry"]),
            _pool_catalog_json=_snapshot_json(document["pool_catalog"]),
        )

    def _snapshot_from_path(
        self,
        path: Path,
        *,
        source: str,
        enforce_expiry: bool,
        enforce_future_time: bool = True,
    ) -> ConfigSnapshot:
        return self.validate_bytes(
            _read_limited(path),
            source=source,
            enforce_expiry=enforce_expiry,
            enforce_future_time=enforce_future_time,
        )

    def load_snapshot(self) -> ConfigSnapshot | None:
        candidates = (
            (self.current_path, "current", True, True),
            (self.previous_path, "previous", True, True),
            (self.builtin_path, "builtin", False, False),
        )
        with self._lock:
            for path, source, enforce_expiry, enforce_future_time in candidates:
                if not path.is_file():
                    continue
                try:
                    return self._snapshot_from_path(
                        path,
                        source=source,
                        enforce_expiry=enforce_expiry,
                        enforce_future_time=enforce_future_time,
                    )
                except ConfigError as error:
                    self._log(
                        "local_config_rejected",
                        source=source,
                        reason=str(error),
                    )
        return None

    def _load_state(self) -> tuple[int, str, str]:
        try:
            if self.state_path.stat().st_size > MAX_STATE_BYTES:
                return 0, "", ""
            with self.state_path.open("rb") as stream:
                raw_state = stream.read(MAX_STATE_BYTES + 1)
            if len(raw_state) > MAX_STATE_BYTES:
                return 0, "", ""
            state = json.loads(raw_state.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return 0, "", ""
        if not isinstance(state, dict):
            return 0, "", ""
        version = state.get("highest_config_version")
        bundle_hash = state.get("highest_bundle_sha256")
        if type(version) is not int or version <= 0:
            return 0, "", ""
        if (
            not isinstance(bundle_hash, str)
            or re.fullmatch(r"[0-9A-Fa-f]{64}", bundle_hash) is None
        ):
            bundle_hash = ""
        return (
            version,
            bundle_hash.upper(),
            _valid_etag(state.get("remote_etag")),
        )

    def _write_state(self, snapshot: ConfigSnapshot, etag: str) -> None:
        state = {
            "schema_version": 1,
            "highest_config_version": snapshot.config_version,
            "highest_bundle_sha256": snapshot.bundle_sha256,
            "accepted_at": now_iso(),
            "config_id": snapshot.config_id,
        }
        verified_etag = _valid_etag(etag)
        if verified_etag:
            state["remote_etag"] = verified_etag
        atomic_write_json(self.state_path, state)

    def _known_snapshots(self) -> list[ConfigSnapshot]:
        snapshots: list[ConfigSnapshot] = []
        for path, source, enforce_future_time in (
            (self.current_path, "current", True),
            (self.previous_path, "previous", True),
            (self.builtin_path, "builtin", False),
        ):
            if not path.is_file():
                continue
            try:
                snapshots.append(
                    self._snapshot_from_path(
                        path,
                        source=source,
                        enforce_expiry=False,
                        enforce_future_time=enforce_future_time,
                    )
                )
            except ConfigError:
                continue
        return snapshots

    def _conditional_etag(self) -> str:
        with self._lock:
            state_version, state_hash, state_etag = self._load_state()
            if not state_hash or not state_etag:
                return ""
            if any(
                snapshot.config_version == state_version
                and snapshot.bundle_sha256 == state_hash
                for snapshot in self._known_snapshots()
            ):
                return state_etag
        return ""

    @staticmethod
    def _atomic_write_bytes(path: Path, raw: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(
            f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def activate_bytes(self, raw: bytes, *, etag: str = "") -> str:
        candidate = self.validate_bytes(
            raw,
            source="remote",
            enforce_expiry=True,
        )
        persisted_raw = _snapshot_json(_decode_json(raw)).encode("utf-8") + b"\n"
        with self._lock:
            known = self._known_snapshots()
            state_version, state_hash, _state_etag = self._load_state()
            high_version = max(
                [state_version, *(snapshot.config_version for snapshot in known)],
                default=0,
            )
            known_hashes = {
                snapshot.bundle_sha256
                for snapshot in known
                if snapshot.config_version == high_version
            }
            if state_version == high_version and state_hash:
                known_hashes.add(state_hash)
            if candidate.config_version < high_version:
                raise ConfigRollbackError(
                    f"configuration rollback {candidate.config_version} < {high_version}"
                )
            if candidate.config_version == high_version:
                if candidate.bundle_sha256 in known_hashes:
                    self._write_state(candidate, etag)
                    return "current"
                raise ConfigRollbackError(
                    "same configuration version has different signed content"
                )

            old_current: bytes | None = None
            if self.current_path.is_file():
                try:
                    old_current = _read_limited(self.current_path)
                    self.validate_bytes(
                        old_current,
                        source="current",
                        enforce_expiry=False,
                    )
                except ConfigError:
                    old_current = None

            staging_path = self.config_root / ".candidate.json"
            self._atomic_write_bytes(staging_path, persisted_raw)
            try:
                staged = self._snapshot_from_path(
                    staging_path,
                    source="remote",
                    enforce_expiry=True,
                )
                if staged.bundle_sha256 != candidate.bundle_sha256:
                    raise ConfigValidationError("staged configuration changed")
                if old_current is not None:
                    self._atomic_write_bytes(self.previous_path, old_current)
                os.replace(staging_path, self.current_path)
                try:
                    activated = self._snapshot_from_path(
                        self.current_path,
                        source="current",
                        enforce_expiry=True,
                    )
                except ConfigError:
                    if old_current is not None:
                        self._atomic_write_bytes(self.current_path, old_current)
                    else:
                        try:
                            self.current_path.unlink(missing_ok=True)
                        except OSError:
                            pass
                    raise
                if activated.bundle_sha256 != candidate.bundle_sha256:
                    if old_current is not None:
                        self._atomic_write_bytes(self.current_path, old_current)
                    else:
                        try:
                            self.current_path.unlink(missing_ok=True)
                        except OSError:
                            pass
                    raise ConfigValidationError("activated configuration changed")
                self._write_state(activated, etag)
            finally:
                try:
                    staging_path.unlink(missing_ok=True)
                except OSError:
                    pass
        self._log(
            "remote_config_activated",
            config_id=candidate.config_id,
            config_version=candidate.config_version,
            bundle_sha256=candidate.bundle_sha256,
        )
        return "activated"

    def check_for_updates(self) -> str:
        if not self.remote_url:
            return "disabled"
        try:
            state_etag = self._conditional_etag()
            fetched = (
                self._fetcher(self.remote_url)
                if self._fetcher is not None
                else _default_fetch(self.remote_url, state_etag)
            )
            if isinstance(fetched, bytes):
                response = FetchResult(body=fetched)
            elif isinstance(fetched, FetchResult):
                response = fetched
            else:
                raise ConfigValidationError(
                    "configuration fetcher returned an invalid result"
                )
            if response.not_modified:
                if (
                    response.body is not None
                    or not state_etag
                    or _valid_etag(response.etag) != state_etag
                ):
                    raise ConfigValidationError(
                        "not-modified response has no verified ETag basis"
                    )
                self._log("remote_config_check_complete", result="unchanged")
                return "unchanged"
            if response.body is None:
                raise ConfigValidationError(
                    "configuration response has no body"
                )
            result = self.activate_bytes(response.body, etag=response.etag)
        except Exception as error:
            self._log(
                "remote_config_check_failed",
                reason=f"{type(error).__name__}: {error}",
            )
            return "failed"
        self._log("remote_config_check_complete", result=result)
        return result

    def start_background_check(self) -> threading.Thread | None:
        if not self.remote_url:
            return None
        with self._background_lock:
            if (
                self._background_thread is not None
                and self._background_thread.is_alive()
            ):
                return self._background_thread

            def runner() -> None:
                try:
                    self.check_for_updates()
                finally:
                    with self._background_lock:
                        self._background_thread = None

            thread = threading.Thread(
                target=runner,
                name="yka-config-update",
                daemon=True,
            )
            self._background_thread = thread
            thread.start()
            return thread


_DEFAULT_MANAGER: ConfigManager | None = None
_DEFAULT_MANAGER_LOCK = threading.Lock()


def get_default_config_manager() -> ConfigManager:
    global _DEFAULT_MANAGER
    with _DEFAULT_MANAGER_LOCK:
        if _DEFAULT_MANAGER is None:
            _DEFAULT_MANAGER = ConfigManager()
        return _DEFAULT_MANAGER


def load_config_snapshot_or_none() -> ConfigSnapshot | None:
    return get_default_config_manager().load_snapshot()


def start_default_background_check() -> threading.Thread | None:
    return get_default_config_manager().start_background_check()
