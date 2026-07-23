from __future__ import annotations

import json
from pathlib import Path

import pytest

import YKACompatibility
import YKAReport
from YKAReport import (
    CAPTURE_CLEANUP_FILENAME,
    REPORT_FILENAME,
    WECHAT_EXPORT_FILENAME,
    analyze_session,
    build_live_coverage,
    build_session_report,
    cleanup_session_capture_files,
    persist_wechat_export,
)


def _empty_session(path: Path) -> Path:
    path.mkdir(parents=True)
    (path / "pcap").mkdir()
    (path / "session.json").write_text("{}", encoding="utf-8")
    (path / "flows.json").write_text("[]", encoding="utf-8")
    (path / "events.jsonl").write_text("", encoding="utf-8")
    return path


def test_build_session_report_persists_final_report(tmp_path: Path) -> None:
    session = _empty_session(tmp_path / "session")
    (session / "status.json").write_text('{"state":"stopped"}', encoding="utf-8")
    report = build_session_report(session)
    assert isinstance(report, dict)
    assert report["persistence"]["state"] == "final"
    persisted = json.loads((session / REPORT_FILENAME).read_text(encoding="utf-8"))
    assert persisted == report


def test_analyze_session_persists_final_report(tmp_path: Path) -> None:
    session = _empty_session(tmp_path / "session")
    report = analyze_session(session)
    assert json.dumps(report, ensure_ascii=False)
    assert (session / REPORT_FILENAME).is_file()
    assert report["persistence"]["state"] == "final"


def test_analyze_session_forwards_frozen_config_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session = tmp_path / "session"
    snapshot = object()
    calls = []

    def build(path: Path, *, config_snapshot=None):
        calls.append((path, config_snapshot))
        return {"ok": True}

    monkeypatch.setattr(YKAReport, "build_session_report", build)

    assert analyze_session(session, config_snapshot=snapshot) == {"ok": True}
    assert calls == [(session, snapshot)]


def test_missing_signed_configuration_is_explicit_generic_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session = _empty_session(tmp_path / "session")
    monkeypatch.setattr(
        YKACompatibility,
        "load_config_snapshot_or_none",
        lambda: None,
    )
    monkeypatch.setattr(
        YKAReport,
        "load_config_snapshot_or_none",
        lambda: None,
    )

    report = build_session_report(session)
    compatibility = report["protocol_decode"]["compatibility_profile"]

    assert compatibility["profile_id"] == "generic-content-fallback"
    assert compatibility["profile_mode"] == "generic_content_fallback"
    assert compatibility["resolution_mode"] == "generic_content_fallback"
    assert compatibility["configuration"]["source"] == "generic"
    assert (
        compatibility["configuration"]["status"]
        == "signed_configuration_unavailable"
    )


def test_live_coverage_is_lightweight_and_persisted(tmp_path: Path) -> None:
    session = _empty_session(tmp_path / "session")
    report = build_live_coverage(session)
    assert report["session_dir"] == str(session.resolve())
    assert isinstance(report["data_coverage"], dict)
    assert "capture_files" not in report
    assert report["persistence"]["state"] == "live"
    assert (session / REPORT_FILENAME).is_file()


def test_live_report_cannot_overwrite_final_report(tmp_path: Path) -> None:
    session = _empty_session(tmp_path / "session")
    final = build_session_report(session)
    live = build_live_coverage(session)
    assert live == final
    assert live["persistence"]["state"] == "final"


def test_export_then_cleanup_removes_only_capture_files(tmp_path: Path) -> None:
    sessions_root = tmp_path / "sessions"
    session = _empty_session(sessions_root / "session")
    (session / "status.json").write_text('{"state":"stopped"}', encoding="utf-8")
    report = build_session_report(session)
    first = session / "pcap" / "first.pcapng"
    second = session / "pcap" / "second.pcap"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    export_path = persist_wechat_export(
        session,
        {
            "schema_version": 1,
            "report_generated_at": report["generated_at"],
            "transports": {"raw_json": "[]"},
        },
        sessions_root=sessions_root,
    )

    result = cleanup_session_capture_files(session, sessions_root=sessions_root)

    assert export_path == session / WECHAT_EXPORT_FILENAME
    assert result["removed_file_count"] == 2
    assert result["removed_bytes"] == 11
    assert not first.exists()
    assert not second.exists()
    assert (session / REPORT_FILENAME).is_file()
    assert (session / WECHAT_EXPORT_FILENAME).is_file()
    assert (session / CAPTURE_CLEANUP_FILENAME).is_file()


def test_cleanup_fails_closed_before_stop_or_matching_export(tmp_path: Path) -> None:
    sessions_root = tmp_path / "sessions"
    session = _empty_session(sessions_root / "session")
    (session / "status.json").write_text(
        '{"state":"capturing"}', encoding="utf-8"
    )
    report = build_session_report(session)
    capture_file = session / "pcap" / "game.pcapng"
    capture_file.write_bytes(b"capture")

    with pytest.raises(RuntimeError, match="尚未停止"):
        cleanup_session_capture_files(session, sessions_root=sessions_root)

    (session / "status.json").write_text('{"state":"stopped"}', encoding="utf-8")
    persist_wechat_export(
        session,
        {"report_generated_at": report["generated_at"] + "-mismatch"},
        sessions_root=sessions_root,
    )
    with pytest.raises(RuntimeError, match="不匹配"):
        cleanup_session_capture_files(session, sessions_root=sessions_root)
    assert capture_file.is_file()


def test_cleanup_rejects_reparse_capture_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sessions_root = tmp_path / "sessions"
    session = _empty_session(sessions_root / "session")
    (session / "status.json").write_text('{"state":"stopped"}', encoding="utf-8")
    report = build_session_report(session)
    capture_file = session / "pcap" / "game.pcapng"
    capture_file.write_bytes(b"capture")
    persist_wechat_export(
        session,
        {"report_generated_at": report["generated_at"]},
        sessions_root=sessions_root,
    )
    original_check = YKAReport._is_link_or_reparse_point
    monkeypatch.setattr(
        YKAReport,
        "_is_link_or_reparse_point",
        lambda path: path == session / "pcap" or original_check(path),
    )

    with pytest.raises(RuntimeError, match="重解析点"):
        cleanup_session_capture_files(session, sessions_root=sessions_root)
    assert capture_file.is_file()


def test_cleanup_retries_windows_file_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sessions_root = tmp_path / "sessions"
    session = _empty_session(sessions_root / "session")
    (session / "status.json").write_text('{"state":"stopped"}', encoding="utf-8")
    report = build_session_report(session)
    capture_file = session / "pcap" / "game.pcapng"
    capture_file.write_bytes(b"capture")
    persist_wechat_export(
        session,
        {"report_generated_at": report["generated_at"]},
        sessions_root=sessions_root,
    )
    original_unlink = Path.unlink
    attempts = 0

    def locked_then_available(path: Path, *args, **kwargs) -> None:
        nonlocal attempts
        if path == capture_file:
            attempts += 1
            if attempts < 3:
                raise PermissionError("file is temporarily locked")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", locked_then_available)
    monkeypatch.setattr(YKAReport.time, "sleep", lambda _seconds: None)

    result = cleanup_session_capture_files(session, sessions_root=sessions_root)

    assert attempts == 3
    assert result["removed_file_count"] == 1
    assert not capture_file.exists()
