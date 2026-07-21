from __future__ import annotations

import json
import inspect
from pathlib import Path

import YKAReport
from YKAReport import analyze_session, build_live_coverage, build_session_report


def _empty_session(path: Path) -> Path:
    path.mkdir()
    (path / "pcap").mkdir()
    (path / "session.json").write_text("{}", encoding="utf-8")
    (path / "flows.json").write_text("[]", encoding="utf-8")
    (path / "events.jsonl").write_text("", encoding="utf-8")
    return path


def test_build_session_report_is_memory_only_by_default(tmp_path: Path) -> None:
    session = _empty_session(tmp_path / "session")
    report = build_session_report(session)
    assert isinstance(report, dict)
    assert not (session / "reports").exists()


def test_analyze_session_is_memory_only_by_default(tmp_path: Path) -> None:
    session = _empty_session(tmp_path / "session")
    report = analyze_session(session)
    assert json.dumps(report, ensure_ascii=False)
    assert not (session / "reports").exists()


def test_live_coverage_is_lightweight_and_memory_only(tmp_path: Path) -> None:
    session = _empty_session(tmp_path / "session")
    report = build_live_coverage(session)
    assert report["session_dir"] == str(session.resolve())
    assert isinstance(report["data_coverage"], dict)
    assert "capture_files" not in report
    assert not (session / "reports").exists()


def test_report_module_exposes_no_persistence_switch_or_exporter() -> None:
    assert "persist" not in inspect.signature(build_session_report).parameters
    assert "persist" not in inspect.signature(analyze_session).parameters
    assert not hasattr(YKAReport, "export_report")
