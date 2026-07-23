from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import threading
import time

import pytest

import YKAConfigManager as config_module
from YKACompactCodec import load_catalog
from YKACompatibility import load_compatibility_profile
from YKAConfigManager import (
    CONFIG_URL_ENV,
    DEFAULT_REMOTE_URL,
    MAX_BUNDLE_BYTES,
    MAX_STATE_BYTES,
    ConfigManager,
    ConfigRollbackError,
    ConfigValidationError,
    FetchResult,
)
from YKAReport import _decode_game_traffic
from YKAWechatImport import load_pool_catalog


ROOT = Path(__file__).resolve().parents[1]
BUILTIN_PATH = ROOT / "DatAnDict" / "YKAConfigBuiltin.json"
TRUST_PATH = ROOT / "DatAnDict" / "YKAConfigTrust.json"


def _document() -> dict:
    value = json.loads(BUILTIN_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _raw(document: dict) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _section_hash(value: dict) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest().upper()


def _refresh_section_hashes(document: dict) -> None:
    for name in (
        "compatibility_profiles",
        "compact_catalog",
        "compact_registry",
        "pool_catalog",
    ):
        document["content_sha256"][name] = _section_hash(document[name])


def _issued_time() -> datetime:
    value = str(_document()["issued_at"])
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def _manager(
    tmp_path: Path,
    *,
    now: datetime | None = None,
    fetcher=None,
    remote_url: str = "",
) -> ConfigManager:
    instant = now or (_issued_time() + timedelta(hours=1))
    return ConfigManager(
        data_root=tmp_path / "config",
        builtin_path=BUILTIN_PATH,
        trust_path=TRUST_PATH,
        remote_url=remote_url,
        now=lambda: instant,
        fetcher=fetcher,
    )


def _unsigned_version(version: int, *, config_id: str | None = None) -> bytes:
    document = _document()
    document["config_version"] = version
    document["config_id"] = config_id or f"test-v{version:08d}"
    return _raw(document)


def _ignore_signature(
    monkeypatch: pytest.MonkeyPatch,
    manager: ConfigManager,
) -> None:
    monkeypatch.setattr(manager, "_verify_signature", lambda _document: None)


def test_builtin_signature_and_all_sections_validate(tmp_path: Path) -> None:
    snapshot = _manager(tmp_path).load_snapshot()

    assert snapshot is not None
    assert snapshot.source == "builtin"
    assert snapshot.config_version == 1
    assert snapshot.config_id == "20260723T074022Z-v00000001"
    assert len(snapshot.pool_catalog["pools"]) == 329
    assert snapshot.compact_catalog["catalog_id"] == "00000102"


def test_snapshot_sections_are_fresh_copies(tmp_path: Path) -> None:
    snapshot = _manager(tmp_path).load_snapshot()
    assert snapshot is not None

    first = snapshot.pool_catalog
    first["pools"].clear()

    assert len(snapshot.pool_catalog["pools"]) == 329


def test_snapshot_feeds_protocol_and_export_catalog_consumers(
    tmp_path: Path,
) -> None:
    snapshot = _manager(tmp_path).load_snapshot()
    assert snapshot is not None

    profile = load_compatibility_profile(snapshot=snapshot)
    compact = load_catalog(
        snapshot.compact_catalog,
        snapshot.compact_registry,
    )
    pool = load_pool_catalog(snapshot.pool_catalog)
    protocol, _coverage, errors = _decode_game_traffic(
        [],
        config_snapshot=snapshot,
    )

    assert profile.catalog_bundle_id == compact["catalog_id"] == "00000102"
    assert len(pool["pools"]) == 329
    assert errors == []
    assert protocol["compatibility_profile"]["configuration"] == (
        snapshot.audit_metadata()
    )


def test_real_signature_tamper_is_rejected(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    document = _document()
    document["config_id"] = "tampered"

    with pytest.raises(ConfigValidationError, match="signature verification failed"):
        manager.validate_bytes(
            _raw(document),
            source="test",
            enforce_expiry=True,
        )


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (
            b'{"schema_version":1,"schema_version":1}',
            "duplicate JSON key",
        ),
        (b'{"value":NaN}', "non-finite JSON number"),
    ],
)
def test_ambiguous_json_is_rejected(
    tmp_path: Path,
    raw: bytes,
    message: str,
) -> None:
    with pytest.raises(ConfigValidationError, match=message):
        _manager(tmp_path).validate_bytes(
            raw,
            source="test",
            enforce_expiry=True,
        )


@pytest.mark.parametrize(
    "section",
    [
        "compatibility_profiles",
        "compact_catalog",
        "compact_registry",
        "pool_catalog",
    ],
)
def test_each_section_hash_tamper_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    section: str,
) -> None:
    manager = _manager(tmp_path)
    _ignore_signature(monkeypatch, manager)
    document = _document()
    document[section]["test_tamper"] = True

    with pytest.raises(ConfigValidationError, match=f"{section} section hash"):
        manager.validate_bytes(
            _raw(document),
            source="test",
            enforce_expiry=True,
        )


def test_expired_current_falls_back_to_previous(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    now = _issued_time() + timedelta(days=10)
    manager = _manager(tmp_path, now=now)
    _ignore_signature(monkeypatch, manager)
    manager.config_root.mkdir(parents=True)
    expired = _document()
    expired["config_version"] = 2
    expired["config_id"] = "expired-current"
    expired["issued_at"] = (now - timedelta(days=2)).isoformat()
    expired["expires_at"] = (now - timedelta(days=1)).isoformat()
    manager.current_path.write_bytes(_raw(expired))
    manager.previous_path.write_bytes(BUILTIN_PATH.read_bytes())

    snapshot = manager.load_snapshot()

    assert snapshot is not None
    assert snapshot.source == "previous"
    assert snapshot.config_version == 1


def test_expired_bundled_configuration_remains_last_resort(tmp_path: Path) -> None:
    manager = _manager(
        tmp_path,
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )

    snapshot = manager.load_snapshot()

    assert snapshot is not None
    assert snapshot.source == "builtin"


def test_bundled_anchor_ignores_runtime_future_clock(tmp_path: Path) -> None:
    manager = _manager(
        tmp_path,
        now=_issued_time() - timedelta(days=365),
    )
    manager.config_root.mkdir(parents=True)
    manager.current_path.write_bytes(BUILTIN_PATH.read_bytes())

    snapshot = manager.load_snapshot()

    assert snapshot is not None
    assert snapshot.source == "builtin"


def test_bundled_anchor_still_requires_issue_before_expiry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    _ignore_signature(monkeypatch, manager)
    document = _document()
    document["expires_at"] = document["issued_at"]

    with pytest.raises(ConfigValidationError, match="precedes issue time"):
        manager.validate_bytes(
            _raw(document),
            source="builtin",
            enforce_expiry=False,
            enforce_future_time=False,
        )


def test_corrupt_current_and_previous_fall_back_to_builtin(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    manager.config_root.mkdir(parents=True)
    manager.current_path.write_bytes(b"{broken")
    manager.previous_path.write_bytes(b"[]")

    snapshot = manager.load_snapshot()

    assert snapshot is not None
    assert snapshot.source == "builtin"


def test_all_invalid_signed_candidates_return_no_snapshot(tmp_path: Path) -> None:
    invalid_builtin = tmp_path / "invalid-builtin.json"
    invalid_builtin.write_bytes(b"{broken")
    manager = ConfigManager(
        data_root=tmp_path / "config",
        builtin_path=invalid_builtin,
        trust_path=TRUST_PATH,
        remote_url="",
        now=lambda: _issued_time() + timedelta(hours=1),
    )
    manager.config_root.mkdir(parents=True)
    manager.current_path.write_bytes(b"[]")
    manager.previous_path.write_bytes(b'{"schema_version":1}')

    assert manager.load_snapshot() is None


def test_oversized_state_is_ignored_without_parsing(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    manager.config_root.mkdir(parents=True)
    manager.state_path.write_bytes(b"{" + b" " * MAX_STATE_BYTES + b"}")

    assert manager._load_state() == (0, "", "")
    assert manager._conditional_etag() == ""


def test_remote_rollback_and_same_version_equivocation_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    _ignore_signature(monkeypatch, manager)

    assert manager.activate_bytes(_unsigned_version(3)) == "activated"
    assert manager.activate_bytes(_unsigned_version(3)) == "current"
    with pytest.raises(ConfigRollbackError, match="rollback"):
        manager.activate_bytes(_unsigned_version(2))
    with pytest.raises(ConfigRollbackError, match="different signed content"):
        manager.activate_bytes(
            _unsigned_version(3, config_id="test-v00000003-different")
        )


def test_atomic_activation_retains_previous_valid_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    _ignore_signature(monkeypatch, manager)

    assert manager.activate_bytes(_unsigned_version(2)) == "activated"
    assert manager.activate_bytes(_unsigned_version(3)) == "activated"
    previous = manager._snapshot_from_path(
        manager.previous_path,
        source="previous",
        enforce_expiry=True,
    )
    current = manager.load_snapshot()

    assert previous.config_version == 2
    assert current is not None
    assert current.source == "current"
    assert current.config_version == 3
    assert load_catalog(
        current.compact_catalog,
        current.compact_registry,
    )["catalog_id"] == "00000102"


def test_offline_update_failure_keeps_local_fallback(tmp_path: Path) -> None:
    def offline(_url: str) -> bytes:
        raise OSError("offline")

    manager = _manager(
        tmp_path,
        fetcher=offline,
        remote_url=DEFAULT_REMOTE_URL,
    )

    assert manager.check_for_updates() == "failed"
    snapshot = manager.load_snapshot()
    assert snapshot is not None
    assert snapshot.source == "builtin"


def test_verified_same_content_noop_persists_etag(tmp_path: Path) -> None:
    etag = '"verified-v1"'
    manager = _manager(
        tmp_path,
        fetcher=lambda _url: FetchResult(
            body=BUILTIN_PATH.read_bytes(),
            etag=etag,
        ),
        remote_url=DEFAULT_REMOTE_URL,
    )

    assert manager.check_for_updates() == "current"
    state = json.loads(manager.state_path.read_text(encoding="utf-8"))
    assert state["highest_config_version"] == 1
    assert state["remote_etag"] == etag
    assert not manager.current_path.exists()


def test_not_modified_uses_only_previously_verified_etag(tmp_path: Path) -> None:
    etag = '"verified-v1"'
    manager = _manager(
        tmp_path,
        fetcher=lambda _url: FetchResult(
            body=BUILTIN_PATH.read_bytes(),
            etag=etag,
        ),
        remote_url=DEFAULT_REMOTE_URL,
    )
    assert manager.check_for_updates() == "current"
    manager._fetcher = lambda _url: FetchResult(
        body=None,
        etag=etag,
        not_modified=True,
    )

    assert manager.check_for_updates() == "unchanged"


@pytest.mark.parametrize("response_etag", ["", '"different"'])
def test_not_modified_rejects_missing_or_mismatched_etag(
    tmp_path: Path,
    response_etag: str,
) -> None:
    etag = '"verified-v1"'
    manager = _manager(
        tmp_path,
        fetcher=lambda _url: FetchResult(
            body=BUILTIN_PATH.read_bytes(),
            etag=etag,
        ),
        remote_url=DEFAULT_REMOTE_URL,
    )
    assert manager.check_for_updates() == "current"
    manager._fetcher = lambda _url: FetchResult(
        body=None,
        etag=response_etag,
        not_modified=True,
    )

    assert manager.check_for_updates() == "failed"


def test_invalid_remote_bundle_cannot_replace_verified_etag(tmp_path: Path) -> None:
    old_etag = '"verified-v1"'
    manager = _manager(
        tmp_path,
        fetcher=lambda _url: FetchResult(
            body=BUILTIN_PATH.read_bytes(),
            etag=old_etag,
        ),
        remote_url=DEFAULT_REMOTE_URL,
    )
    assert manager.check_for_updates() == "current"
    tampered = _document()
    tampered["config_id"] = "tampered"
    manager._fetcher = lambda _url: FetchResult(
        body=_raw(tampered),
        etag='"untrusted"',
    )

    assert manager.check_for_updates() == "failed"
    state = json.loads(manager.state_path.read_text(encoding="utf-8"))
    assert state["remote_etag"] == old_etag


def test_corrupt_local_copy_disables_conditional_etag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    _ignore_signature(monkeypatch, manager)
    assert (
        manager.activate_bytes(
            _unsigned_version(2),
            etag='"verified-v2"',
        )
        == "activated"
    )
    assert manager._conditional_etag() == '"verified-v2"'
    manager.current_path.write_bytes(b"{broken")

    assert manager._conditional_etag() == ""


def test_default_fetch_sends_if_none_match_and_returns_response_etag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}

    class Response:
        headers = {
            "Content-Length": str(len(BUILTIN_PATH.read_bytes())),
            "ETag": '"response-v2"',
        }

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return BUILTIN_PATH.read_bytes()

    class Opener:
        def open(self, request, *, timeout: float):
            captured["request"] = request
            captured["timeout"] = timeout
            return Response()

    monkeypatch.setattr(
        config_module,
        "build_opener",
        lambda _handler: Opener(),
    )

    result = config_module._default_fetch(
        DEFAULT_REMOTE_URL,
        '"verified-v1"',
    )

    assert result.body == BUILTIN_PATH.read_bytes()
    assert result.etag == '"response-v2"'
    assert result.not_modified is False
    assert captured["request"].get_header("If-none-match") == '"verified-v1"'


def test_default_fetch_maps_http_304_to_not_modified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Opener:
        def open(self, request, *, timeout: float):
            raise config_module.HTTPError(
                request.full_url,
                304,
                "Not Modified",
                {"ETag": '"verified-v1"'},
                io.BytesIO(),
            )

    monkeypatch.setattr(
        config_module,
        "build_opener",
        lambda _handler: Opener(),
    )

    result = config_module._default_fetch(
        DEFAULT_REMOTE_URL,
        '"verified-v1"',
    )

    assert result == FetchResult(
        body=None,
        etag='"verified-v1"',
        not_modified=True,
    )


@pytest.mark.parametrize("response_etag", [None, '"different"'])
def test_default_fetch_rejects_304_without_exact_response_etag(
    monkeypatch: pytest.MonkeyPatch,
    response_etag: str | None,
) -> None:
    headers = {} if response_etag is None else {"ETag": response_etag}

    class Opener:
        def open(self, request, *, timeout: float):
            raise config_module.HTTPError(
                request.full_url,
                304,
                "Not Modified",
                headers,
                io.BytesIO(),
            )

    monkeypatch.setattr(
        config_module,
        "build_opener",
        lambda _handler: Opener(),
    )

    with pytest.raises(ConfigValidationError, match="does not match"):
        config_module._default_fetch(
            DEFAULT_REMOTE_URL,
            '"verified-v1"',
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://gitee.com/yuzeis/yka/raw/main/config/latest.json",
        "https://user@gitee.com/yuzeis/yka/raw/main/config/latest.json",
        "https://" + "user:pass@" + "gitee.com/yuzeis/yka/raw/main/config/latest.json",
        "https://gitee.com:443/yuzeis/yka/raw/main/config/latest.json",
        "https://gitee.com:8443/yuzeis/yka/raw/main/config/latest.json",
        "https://gitee.com/yuzeis/yka/raw/main/config/latest.json#fragment",
        "https://[invalid/yuzeis/yka/raw/main/config/latest.json",
    ],
)
def test_default_fetch_rejects_non_strict_urls(url: str) -> None:
    with pytest.raises(ConfigValidationError, match="strict HTTPS"):
        config_module._default_fetch(url)


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (
            DEFAULT_REMOTE_URL,
            "https://user@raw.giteeusercontent.com/yuzeis/yka/main/config/latest.json",
        ),
        (
            DEFAULT_REMOTE_URL,
            "https://raw.giteeusercontent.com:443/yuzeis/yka/main/config/latest.json",
        ),
        (
            DEFAULT_REMOTE_URL,
            "http://raw.giteeusercontent.com/yuzeis/yka/main/config/latest.json",
        ),
        (
            "https://gitee.com:443/yuzeis/yka/raw/main/config/latest.json",
            "https://raw.giteeusercontent.com/yuzeis/yka/main/config/latest.json",
        ),
    ],
)
def test_redirect_rejects_userinfo_or_explicit_ports(
    source: str,
    target: str,
) -> None:
    handler = config_module._RestrictedRedirectHandler()
    request = config_module.Request(source)

    with pytest.raises(config_module.HTTPError, match="not allowed"):
        handler.redirect_request(
            request,
            io.BytesIO(),
            302,
            "Found",
            {},
            target,
        )


def test_background_check_returns_without_waiting_for_network(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()

    def blocked(_url: str) -> bytes:
        entered.set()
        release.wait(timeout=3)
        raise OSError("offline")

    manager = _manager(
        tmp_path,
        fetcher=blocked,
        remote_url=DEFAULT_REMOTE_URL,
    )
    started_at = time.monotonic()
    thread = manager.start_background_check()
    elapsed = time.monotonic() - started_at

    assert thread is not None
    assert elapsed < 0.25
    assert entered.wait(timeout=1)
    release.set()
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_bundle_size_limit_is_enforced(tmp_path: Path) -> None:
    manager = _manager(tmp_path)

    with pytest.raises(ConfigValidationError, match="exceeds"):
        manager.validate_bytes(
            b" " * (MAX_BUNDLE_BYTES + 1),
            source="test",
            enforce_expiry=True,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", 2, "unsupported configuration schema"),
        ("target_package", "example.invalid", "targets another package"),
        ("min_shell_version", 2, "requires a newer shell"),
    ],
)
def test_incompatible_metadata_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field: str,
    value,
    message: str,
) -> None:
    manager = _manager(tmp_path)
    _ignore_signature(monkeypatch, manager)
    document = _document()
    document[field] = value

    with pytest.raises(ConfigValidationError, match=message):
        manager.validate_bytes(
            _raw(document),
            source="test",
            enforce_expiry=True,
        )


def test_cross_catalog_binding_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    _ignore_signature(monkeypatch, manager)
    document = _document()
    document["compatibility_profiles"]["profiles"][0][
        "catalog_bundle_id"
    ] = "00000101"
    _refresh_section_hashes(document)

    with pytest.raises(ConfigValidationError, match="not bound"):
        manager.validate_bytes(
            _raw(document),
            source="test",
            enforce_expiry=True,
        )


def test_pool_key_order_must_match_compact_catalog(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    _ignore_signature(monkeypatch, manager)
    document = _document()
    pools = document["pool_catalog"]["pools"]
    pools[0], pools[1] = pools[1], pools[0]
    _refresh_section_hashes(document)

    with pytest.raises(ConfigValidationError, match="pool key order"):
        manager.validate_bytes(
            _raw(document),
            source="test",
            enforce_expiry=True,
        )


def test_compact_internal_hash_rejects_key_reordering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    _ignore_signature(monkeypatch, manager)
    document = _document()
    document["compact_catalog"] = dict(
        sorted(document["compact_catalog"].items())
    )
    _refresh_section_hashes(document)

    with pytest.raises(ConfigValidationError, match="compact catalog content hash"):
        manager.validate_bytes(
            _raw(document),
            source="test",
            enforce_expiry=True,
        )


def test_environment_url_override_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    override = "https://config.example.test/latest.json"
    monkeypatch.setenv(CONFIG_URL_ENV, override)

    manager = ConfigManager(
        data_root=tmp_path / "config",
        builtin_path=BUILTIN_PATH,
        trust_path=TRUST_PATH,
    )

    assert manager.remote_url == override
