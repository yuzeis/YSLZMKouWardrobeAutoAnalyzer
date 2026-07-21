from __future__ import annotations

import queue
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import YKAApp
from YKAQR import (
    QR_KIND_C1_BASE64,
    QR_KIND_COMPRESSED_JSON,
    QRCapacityError,
    QRMetadata,
)
from YKAApp import (
    APP_CODENAME,
    APP_NAME,
    APP_TITLE,
    APP_VERSION,
    COMPACT_CATALOG_PATH,
    COMPACT_REGISTRY_PATH,
    LICENSE_PATH,
    POOL_CATALOG_PATH,
    PROTOCOL_SPEC_PATH,
    ReporterApp,
    SOURCE_REPOSITORY_URL,
    STARTUP_NOTICES,
    show_startup_notices,
)


class _RootStub:
    def __init__(self) -> None:
        self.destroyed = False
        self.after_calls: list[tuple[int, object]] = []

    def destroy(self) -> None:
        self.destroyed = True

    def after(self, delay: int, callback) -> None:
        self.after_calls.append((delay, callback))


class _BadgeStub:
    def __init__(self) -> None:
        self.semantic = ""
        self.label = ""

    def set(self, semantic: str, label: str) -> None:
        self.semantic = semantic
        self.label = label


class _ImmediateThread:
    def __init__(self, *, target, name: str, daemon: bool) -> None:
        self.target = target

    def start(self) -> None:
        self.target()


def test_release_metadata_is_finalized() -> None:
    assert APP_NAME == "YSLZMKouWardrobeAutoAnalyzer"
    assert APP_VERSION == "ver1.0-beta1"
    assert APP_CODENAME == "Gnadenfülle"
    assert APP_TITLE == (
        "YSLZMKouWardrobeAutoAnalyzer ver1.0-beta1 - Gnadenfülle"
    )


def test_report_persistence_smoke_covers_cleanup() -> None:
    result = YKAApp._report_persistence_smoke()
    assert result == {
        "live_state": "live",
        "final_state": "final",
        "report_exists": True,
        "export_exists": True,
        "removed_capture_files": 1,
        "capture_removed": True,
    }


def test_qr_capacity_feedback_guides_to_compact_transports() -> None:
    error = QRCapacityError("二维码容量不足")
    assert YKAApp.qr_error_text(QR_KIND_COMPRESSED_JSON, error) == (
        "二维码容量不足；请切换 C1 Base64 或 C1 Base4096"
    )
    assert YKAApp.qr_error_text(QR_KIND_C1_BASE64, error) == "二维码容量不足"

    metadata = QRMetadata(
        kind=QR_KIND_COMPRESSED_JSON,
        version=23,
        error_correction="L",
        pixels=936,
        modules=109,
        box_size=8,
        border=4,
        characters=1000,
        utf8_bytes=1000,
        high_density=True,
    )
    message = YKAApp.qr_metadata_text(QR_KIND_COMPRESSED_JSON, metadata)
    assert "高密度" in message
    assert "C1 Base64" in message
    assert "C1 Base4096" in message


def test_startup_notices_cover_required_disclosures() -> None:
    assert len(STARTUP_NOTICES) == 3
    assert "封禁" in STARTUP_NOTICES[0].body
    assert "法律法规" in STARTUP_NOTICES[0].body
    assert "不承担" in STARTUP_NOTICES[0].body
    assert "AGPL-3.0-only" in STARTUP_NOTICES[1].body
    assert "AS IS" in STARTUP_NOTICES[1].body
    assert STARTUP_NOTICES[1].action == "license"
    assert "绝对免费" in STARTUP_NOTICES[2].body
    assert "正式向公众发布时" in STARTUP_NOTICES[2].body
    assert SOURCE_REPOSITORY_URL in STARTUP_NOTICES[2].body
    assert "12 小时内" in STARTUP_NOTICES[2].body
    assert STARTUP_NOTICES[2].action == "repository"


def test_startup_notice_sequence_stops_on_first_rejection() -> None:
    presented: list[tuple[int, str]] = []

    def presenter(_root, _theme, notice, index: int, total: int) -> bool:
        assert total == 3
        presented.append((index, notice.title))
        return index == 1

    assert show_startup_notices(
        object(),
        object(),
        presenter=presenter,
    ) is False
    assert presented == [
        (1, STARTUP_NOTICES[0].title),
        (2, STARTUP_NOTICES[1].title),
    ]


def test_rejecting_startup_notice_exits_before_app_initialization() -> None:
    args = SimpleNamespace(collector_watch=False, smoke_test=False)
    parser = mock.Mock()
    parser.parse_args.return_value = args
    root = mock.Mock()
    theme = object()
    with mock.patch.object(YKAApp, "build_parser", return_value=parser), mock.patch.object(
        YKAApp, "ensure_admin_or_restart", return_value=False
    ), mock.patch.object(
        YKAApp.tk, "Tk", return_value=root
    ), mock.patch.object(
        YKAApp.ui_theme, "Theme", return_value=theme
    ), mock.patch.object(
        YKAApp, "show_startup_notices", return_value=False
    ) as notices, mock.patch.object(YKAApp, "ReporterApp") as reporter:
        assert YKAApp.main() == 0

    root.withdraw.assert_called_once_with()
    notices.assert_called_once_with(root, theme)
    reporter.assert_not_called()
    root.destroy.assert_called_once_with()


def test_normal_start_relaunches_elevated_before_tk() -> None:
    args = SimpleNamespace(collector_watch=False, smoke_test=False)
    parser = mock.Mock()
    parser.parse_args.return_value = args
    with mock.patch.object(YKAApp, "build_parser", return_value=parser), mock.patch.object(
        YKAApp, "ensure_admin_or_restart", return_value=True
    ) as elevate, mock.patch.object(YKAApp.tk, "Tk") as tk_root:
        assert YKAApp.main() == 0

    elevate.assert_called_once_with()
    tk_root.assert_not_called()


def test_admin_restart_command_preserves_source_arguments() -> None:
    with mock.patch.object(YKAApp.sys, "argv", ["YKAApp.py", "--example", "a b"]), mock.patch.object(
        YKAApp.sys, "frozen", False, create=True
    ):
        executable, arguments = YKAApp._admin_restart_command()

    assert executable == YKAApp.sys.executable
    assert Path(arguments[0]).name == "YKAApp.py"
    assert arguments[1:] == ["--example", "a b"]


def test_launch_elevated_uses_pointer_sized_shell_result(tmp_path) -> None:
    executable = tmp_path / "app.exe"
    shell_execute = mock.Mock(return_value=33)
    with mock.patch.object(
        YKAApp.ctypes.windll.shell32,
        "ShellExecuteW",
        shell_execute,
    ), mock.patch.object(YKAApp.sys, "frozen", True, create=True):
        YKAApp._launch_elevated(str(executable), ["--value", "a b"])

    assert shell_execute.restype is YKAApp.ctypes.c_void_p
    assert shell_execute.argtypes[-1] is YKAApp.ctypes.c_int
    assert shell_execute.call_args.args[4] == str(tmp_path.resolve())
    assert '"a b"' in shell_execute.call_args.args[3]


def test_persist_wechat_export_then_cleans_capture(tmp_path) -> None:
    app = object.__new__(ReporterApp)
    app._active_session = tmp_path / "session"
    app._current_report = {
        "generated_at": "2026-07-21T10:00:00+08:00",
        "persistence": {"state": "final", "path": "report.json"},
    }
    artifacts = SimpleNamespace(
        catalog_id="catalog",
        codec_id="codec",
        target_width=261,
        raw_json="[]",
        compressed_json="J1:test",
        c1_base64="C1B64:test",
        c1_base4096="C1B4096:test",
    )
    export_path = tmp_path / "session" / "wechat-export.json"
    cleanup = {"removed_file_count": 2}
    with mock.patch.object(
        YKAApp, "persist_wechat_export", return_value=export_path
    ) as persist, mock.patch.object(
        YKAApp, "cleanup_session_capture_files", return_value=cleanup
    ) as clean:
        result = app._persist_wechat_export_and_cleanup(artifacts)

    assert result == (export_path, cleanup)
    payload = persist.call_args.args[1]
    assert payload["report_generated_at"] == app._current_report["generated_at"]
    assert payload["transports"]["raw_json"] == "[]"
    assert payload["transports"]["c1_base4096"] == "C1B4096:test"
    clean.assert_called_once_with(app._active_session)


def test_raw_wechat_export_persists_without_compact_artifacts(tmp_path) -> None:
    app = object.__new__(ReporterApp)
    app._active_session = tmp_path / "session"
    app._current_report = {
        "generated_at": "2026-07-21T10:00:00+08:00",
        "persistence": {"state": "final", "path": "report.json"},
    }
    export_path = app._active_session / "wechat-export.json"
    with mock.patch.object(
        YKAApp, "persist_wechat_export", return_value=export_path
    ) as persist:
        result = app._persist_raw_wechat_export("[]", 261)

    assert result == export_path
    payload = persist.call_args.args[1]
    assert payload["catalog_id"] is None
    assert payload["codec_id"] is None
    assert payload["transports"] == {"raw_json": "[]"}


def test_raw_import_remains_available_when_compact_generation_fails(
    tmp_path: Path,
) -> None:
    app = object.__new__(ReporterApp)
    app._active_session = tmp_path / "session"
    app._current_report = {
        "generated_at": "2026-07-21T10:00:00+08:00",
        "persistence": {"state": "final", "path": "report.json"},
    }
    app._report_revision = 4
    app.target_image_width_var = mock.Mock()
    app.target_image_width_var.get.return_value = "261"
    app.import_text = object()
    app.import_badge = _BadgeStub()
    app._clear_import_output = mock.Mock()
    app._replace_text = mock.Mock()
    app._append_log = mock.Mock()
    app._set_import_summary = mock.Mock()

    raw_json = '[["p1",0,0]]'
    import_result = SimpleNamespace(
        code=raw_json,
        records=(SimpleNamespace(pool_key="p1"),),
        warnings=("保守匹配",),
    )
    events: list[str] = []

    def persist_raw(_raw_json, _target_width):
        events.append("raw_persisted")
        return app._active_session / "wechat-export.json"

    def fail_compact(*_args, **_kwargs):
        events.append("compact_failed")
        raise YKAApp.ArtifactError("compact failure")

    app._persist_raw_wechat_export = mock.Mock(side_effect=persist_raw)
    with mock.patch.object(
        YKAApp, "generate_import_code_from_report", return_value=import_result
    ), mock.patch.object(
        YKAApp, "build_import_artifacts", side_effect=fail_compact
    ), mock.patch.object(
        YKAApp,
        "cleanup_session_capture_files",
        return_value={"removed_file_count": 1},
    ) as cleanup, mock.patch.object(YKAApp.messagebox, "showwarning") as warning:
        app.generate_wechat_code()

    assert events == ["raw_persisted", "compact_failed"]
    app._replace_text.assert_called_once_with(
        app.import_text,
        raw_json,
        readonly=True,
    )
    assert app._artifact_value("raw") == ("原始 JSON", raw_json)
    assert app.import_badge.label == "原始 JSON 已生成"
    cleanup.assert_called_once_with(app._active_session)
    warning.assert_called_once()


def test_gacha_history_shows_only_observed_draw_quantity() -> None:
    history = {
        "entries": [
            {"count": 1, "results": [{"id": 10}]},
            {"count": 10, "results": [{"id": 20}]},
            {"count": True},
            {"count": -1},
            "malformed",
        ]
    }
    assert ReporterApp._gacha_history_count(history) == 11


def test_browse_history_uses_cumulative_draw_snapshot_without_drawing() -> None:
    report = {
        "data_coverage": {
            "draw_count": {
                "status": "observed_present",
                "snapshot_complete": True,
                "completeness": True,
                "observed_pool_count": 77,
            },
            "gacha_history": {"status": "unobserved", "entries": []},
        }
    }
    snapshot = ReporterApp._browse_status_snapshot(report)
    assert snapshot["history_count"] == 0
    assert snapshot["draw_pool_count"] == 77
    assert snapshot["badges"]["history"] == {
        "semantic": "ok",
        "label": "已浏览 · 77 池抽数",
        "progress": (77, 0),
    }


def test_live_browse_status_is_monotonic_until_final_report() -> None:
    app = object.__new__(ReporterApp)
    app.browse_badges = {"history": _BadgeStub()}
    app._live_browse_badges = {}
    observed = {
        "badges": {
            "history": {
                "semantic": "ok",
                "label": "已浏览 · 77 池抽数",
                "progress": (77, 0),
            }
        }
    }
    empty = {
        "badges": {
            "history": {
                "semantic": "empty",
                "label": "未观测 · 0 池抽数",
                "progress": (0, 0),
            }
        }
    }
    app._apply_browse_snapshot(observed, monotonic=True)
    app._apply_browse_snapshot(empty, monotonic=True)
    assert app.browse_badges["history"].semantic == "ok"
    assert app.browse_badges["history"].label == "已浏览 · 77 池抽数"

    app._apply_browse_snapshot(empty, monotonic=False)
    assert app.browse_badges["history"].semantic == "empty"


def test_live_analysis_is_backgrounded_and_single_flight(tmp_path) -> None:
    session = tmp_path / "session"
    pcap = session / "pcap"
    pcap.mkdir(parents=True)
    (pcap / "game.pcapng").write_bytes(b"pcap-data")
    app = object.__new__(ReporterApp)
    app._events = queue.Queue()
    app._live_analysis_generation = 3
    app._live_analysis_inflight = False
    app._live_analysis_last_started = 0.0
    app._live_analysis_last_revision = None
    status = {
        "state": "capturing",
        "session_dir": str(session),
        "capture_has_packets": True,
        "capture_packets": 10,
    }
    with mock.patch.object(YKAApp.time, "monotonic", return_value=10.0), mock.patch.object(
        YKAApp, "build_live_coverage", return_value={"data_coverage": {}}
    ) as build, mock.patch.object(YKAApp.threading, "Thread", _ImmediateThread):
        app._maybe_start_live_analysis(status)
        app._maybe_start_live_analysis(status)
    build.assert_called_once_with(session.resolve())
    assert app._live_analysis_inflight is True
    assert app._events.qsize() == 1
    assert app._events.get_nowait()[0] == "live"


def test_persistent_live_decode_error_retries_before_diagnostic(tmp_path) -> None:
    session = tmp_path / "session"
    pcap = session / "pcap"
    pcap.mkdir(parents=True)
    (pcap / "game.pcapng").write_bytes(b"incomplete-pcap")
    app = object.__new__(ReporterApp)
    app._events = queue.Queue()
    app._live_analysis_generation = 4
    app._live_analysis_inflight = False
    app._live_analysis_last_started = 0.0
    app._live_analysis_last_revision = None
    app._live_analysis_retry_count = 0
    app._live_decode_warning = ""
    app.capture_traffic_badge = _BadgeStub()
    app.browse_badges = {"history": _BadgeStub()}
    app._append_log = mock.Mock()
    status = {
        "state": "capturing",
        "session_dir": str(session),
        "capture_has_packets": True,
    }
    with mock.patch.object(YKAApp.time, "monotonic", return_value=10.0), mock.patch.object(
        YKAApp,
        "build_live_coverage",
        return_value={"protocol_decode": {"status": "decode_error"}},
    ), mock.patch.object(YKAApp.threading, "Thread", _ImmediateThread):
        app._maybe_start_live_analysis(status)
    kind, _, payload, _ = app._events.get_nowait()
    assert kind == "live_retry"
    app._handle_live_analysis_event(kind, payload)
    assert app._live_analysis_inflight is False
    assert app._live_analysis_last_revision is None
    assert app.capture_traffic_badge.label == ""
    app._handle_live_analysis_event(kind, payload)
    app._handle_live_analysis_event(kind, payload)
    assert app.capture_traffic_badge.label == "无法解码 · 请重启游戏连接"
    assert app.browse_badges["history"].label == "等待可解码连接"


def test_live_result_updates_badges_only_for_current_session() -> None:
    app = object.__new__(ReporterApp)
    app._live_analysis_generation = 5
    app._live_analysis_inflight = True
    app._live_analysis_last_error = ""
    app._last_state = "capturing"
    app._last_capture_session = "current-session"
    app._live_browse_badges = {}
    app.browse_badges = {"history": _BadgeStub()}
    report = {
        "data_coverage": {
            "draw_count": {
                "status": "observed_present",
                "snapshot_complete": True,
                "completeness": True,
                "observed_pool_count": 77,
            },
            "gacha_history": {"status": "unobserved", "entries": []},
        }
    }
    app._handle_live_analysis_event(
        "live",
        {
            "generation": 5,
            "session_dir": "other-session",
            "report": report,
        },
    )
    assert app.browse_badges["history"].label == ""

    app._live_analysis_inflight = True
    app._handle_live_analysis_event(
        "live",
        {
            "generation": 5,
            "session_dir": "current-session",
            "report": report,
        },
    )
    assert app.browse_badges["history"].label == "已浏览 · 77 池抽数"


def test_unresolved_server_stream_shows_restart_diagnostic() -> None:
    report = {
        "protocol_decode": {
            "status": "partial",
            "streams": [
                {
                    "transport_mode": "unresolved",
                    "tcp_payload_bytes": 1296,
                    "complete_frames": 0,
                }
            ],
        },
        "data_coverage": {},
    }
    assert ReporterApp._decode_warning_for_report(report) == (
        "无法解码 · 请重启游戏连接"
    )
    app = object.__new__(ReporterApp)
    app._live_analysis_generation = 6
    app._live_analysis_inflight = True
    app._live_analysis_last_error = ""
    app._live_decode_warning = ""
    app._last_state = "capturing"
    app._last_capture_session = "session"
    app.capture_traffic_badge = _BadgeStub()
    app.browse_badges = {"history": _BadgeStub()}
    app._append_log = mock.Mock()
    app._handle_live_analysis_event(
        "live",
        {
            "generation": 6,
            "session_dir": "session",
            "report": report,
        },
    )
    assert app.capture_traffic_badge.semantic == "warn"
    assert app.capture_traffic_badge.label == "无法解码 · 请重启游戏连接"
    assert app.browse_badges["history"].label == "等待可解码连接"
    app._append_log.assert_called_once()


def test_collector_disappearance_invalidates_live_result() -> None:
    app = object.__new__(ReporterApp)
    app.root = _RootStub()
    app._last_state = "capturing"
    app._last_capture_session = "session"
    app._apply_status = mock.Mock()
    app._maybe_start_live_analysis = mock.Mock()
    app._invalidate_live_analysis = mock.Mock()
    with mock.patch.object(
        YKAApp, "current_capture_status", return_value={"state": "not_started"}
    ):
        app._poll_collector_status()
    app._apply_status.assert_called_once()
    app._invalidate_live_analysis.assert_called_once()
    app._maybe_start_live_analysis.assert_not_called()


def test_invalidating_live_analysis_resets_retry_budget() -> None:
    app = object.__new__(ReporterApp)
    app._live_analysis_generation = 7
    app._live_analysis_inflight = True
    app._live_analysis_last_revision = (("game.pcapng", 10, 20),)
    app._live_analysis_retry_count = 3
    app._invalidate_live_analysis()
    assert app._live_analysis_generation == 8
    assert app._live_analysis_inflight is False
    assert app._live_analysis_last_revision is None
    assert app._live_analysis_retry_count == 0


def test_resources_are_loaded_from_structured_source_folders() -> None:
    assert POOL_CATALOG_PATH.is_file()
    assert COMPACT_CATALOG_PATH.is_file()
    assert COMPACT_REGISTRY_PATH.is_file()
    assert PROTOCOL_SPEC_PATH.is_file()
    assert LICENSE_PATH.is_file()
    license_text = LICENSE_PATH.read_text(encoding="utf-8")
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in license_text
    assert "15. Disclaimer of Warranty." in license_text
    assert POOL_CATALOG_PATH.parent.name == "DatAnDict"
    assert PROTOCOL_SPEC_PATH.parent.name == "Docs"


def test_closing_an_active_gui_stops_capture_before_destroying() -> None:
    root = _RootStub()
    app = object.__new__(ReporterApp)
    app.root = root
    app._last_state = "capturing"
    app._busy_count = 0
    with mock.patch.object(YKAApp.messagebox, "askyesno", return_value=True), mock.patch.object(
        YKAApp, "request_stop", return_value={"state": "stopped"}
    ) as stop:
        app._on_close()
    stop.assert_called_once_with(timeout=30.0)
    assert root.destroyed


def test_closing_is_blocked_while_start_or_analysis_task_is_busy() -> None:
    root = _RootStub()
    app = object.__new__(ReporterApp)
    app.root = root
    app._last_state = "not_started"
    app._busy_count = 1
    with mock.patch.object(YKAApp.messagebox, "showinfo") as notice, mock.patch.object(
        YKAApp, "request_stop"
    ) as stop:
        app._on_close()
    notice.assert_called_once()
    stop.assert_not_called()
    assert not root.destroyed
