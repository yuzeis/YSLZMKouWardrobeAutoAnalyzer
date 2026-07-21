from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import sys
import threading
from types import SimpleNamespace

import pytest

from YKAApp import build_parser as build_app_parser
import YKACapture as capture
import YKACollector as collector


def _interface(
    name: str,
    address: str,
    *,
    identifier: str | None = None,
    virtual: bool = False,
) -> dict[str, object]:
    return {
        "index": 1,
        "identifier": identifier or name,
        "device": identifier or name,
        "name": name,
        "description": name,
        "addresses": [address],
        "backend": "scapy",
        "is_virtual": virtual,
    }


def test_default_route_selects_active_tunnel_before_physical_fallback() -> None:
    interfaces = [
        _interface("Meta", "198.18.0.1", virtual=True),
        _interface("以太网", "192.168.31.179"),
    ]

    selected, reason = capture.select_capture_interfaces(
        interfaces,
        route_ipv4="198.18.0.1",
    )

    assert [item["name"] for item in selected] == ["Meta"]
    assert reason == "default_route_ipv4"


def test_fallback_avoids_virtual_and_link_local_interfaces() -> None:
    interfaces = [
        _interface("VMware", "192.168.195.1", virtual=True),
        _interface("WLAN", "169.254.10.2"),
        _interface("以太网", "192.168.31.179"),
    ]

    selected, reason = capture.select_capture_interfaces(
        interfaces,
        route_ipv4="203.0.113.10",
    )

    assert [item["name"] for item in selected] == ["以太网"]
    assert reason == "physical_ipv4_fallback"


def test_missing_requested_interface_fails_closed() -> None:
    selected, reason = capture.select_capture_interfaces(
        [_interface("以太网", "192.168.31.179")],
        requested_interface="不存在的网卡",
        route_ipv4="192.168.31.179",
    )

    assert selected == []
    assert reason == "requested_interface_not_found"


def test_down_interfaces_are_not_used_as_automatic_fallback() -> None:
    interface = _interface("以太网", "192.168.31.179")
    interface["is_up"] = False

    selected, reason = capture.select_capture_interfaces(
        [interface],
        route_ipv4="203.0.113.10",
    )

    assert selected == []
    assert reason == "no_active_ipv4_interface"


def test_auto_environment_prefers_ready_scapy(monkeypatch: pytest.MonkeyPatch) -> None:
    interface = _interface(
        "Meta",
        "198.18.0.1",
        identifier=r"\Device\NPF_TEST",
        virtual=True,
    )
    monkeypatch.delenv(capture.CAPTURE_BACKEND_ENV, raising=False)
    monkeypatch.delenv(capture.CAPTURE_INTERFACE_ENV, raising=False)
    monkeypatch.setattr(
        capture,
        "inspect_npcap",
        lambda: {"installed": True, "detected_paths": ["wpcap.dll"]},
    )
    monkeypatch.setattr(
        capture,
        "inspect_scapy",
        lambda: {"installed": True, "version": "test", "use_pcap": True, "ready": True},
    )
    monkeypatch.setattr(capture, "list_scapy_interfaces", lambda: [interface])
    monkeypatch.setattr(capture, "default_route_ipv4", lambda: "198.18.0.1")
    monkeypatch.setattr(
        capture,
        "probe_scapy_interface",
        lambda identifier, capture_filter: {
            "attempted": True,
            "ready": True,
            "identifier": identifier,
        },
    )

    result = capture.inspect_capture_environment("tcp port 9227")

    assert result["capture_backend"] == "scapy"
    assert result["selected_interface_ids"] == [r"\Device\NPF_TEST"]
    assert result["selection_reason"] == "default_route_ipv4"
    assert result["backend_ready"] is True


def test_auto_environment_does_not_fall_back_to_dumpcap_after_scapy_probe_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scapy_interface = _interface(
        "Meta",
        "198.18.0.1",
        identifier=r"\Device\NPF_TEST",
        virtual=True,
    )
    dumpcap_interface = dict(scapy_interface)
    dumpcap_interface.update(
        backend="dumpcap",
        identifier="7",
        device=r"\Device\NPF_TEST",
    )
    dumpcap_path = tmp_path / "dumpcap.exe"
    dumpcap_path.touch()
    monkeypatch.delenv(capture.CAPTURE_BACKEND_ENV, raising=False)
    monkeypatch.delenv(capture.CAPTURE_INTERFACE_ENV, raising=False)
    monkeypatch.setattr(capture, "DUMPCAP_PATH", dumpcap_path)
    monkeypatch.setattr(
        capture,
        "inspect_npcap",
        lambda: {"installed": True, "detected_paths": ["wpcap.dll"]},
    )
    monkeypatch.setattr(
        capture,
        "inspect_scapy",
        lambda: {"installed": True, "version": "test", "use_pcap": True, "ready": True},
    )
    monkeypatch.setattr(capture, "list_scapy_interfaces", lambda: [scapy_interface])
    monkeypatch.setattr(capture, "list_dumpcap_interfaces", lambda: [dumpcap_interface])
    monkeypatch.setattr(capture, "default_route_ipv4", lambda: "198.18.0.1")
    monkeypatch.setattr(
        capture,
        "probe_scapy_interface",
        lambda identifier, capture_filter: {
            "attempted": True,
            "ready": False,
            "identifier": identifier,
            "error": "probe failed",
        },
    )
    result = capture.inspect_capture_environment("tcp port 9227")

    assert result["capture_backend"] is None
    assert result["selected_interface_ids"] == [r"\Device\NPF_TEST"]
    assert [item["backend"] for item in result["backend_attempts"]] == ["scapy"]
    assert result["backend_ready"] is False
    assert result["required_components"]["npcap"]["required"] is True
    assert result["required_components"]["tshark"]["required"] is False


def test_explicit_dumpcap_backend_remains_available(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    interface = _interface("以太网", "192.168.31.179", identifier="7")
    dumpcap_path = tmp_path / "dumpcap.exe"
    dumpcap_path.touch()
    monkeypatch.setenv(capture.CAPTURE_BACKEND_ENV, "dumpcap")
    monkeypatch.setattr(capture, "DUMPCAP_PATH", dumpcap_path)
    monkeypatch.setattr(capture, "inspect_npcap", lambda: {"installed": False})
    monkeypatch.setattr(capture, "inspect_scapy", lambda: {"installed": False, "ready": False})
    monkeypatch.setattr(capture, "list_dumpcap_interfaces", lambda: [dict(interface, backend="dumpcap")])
    monkeypatch.setattr(capture, "default_route_ipv4", lambda: "192.168.31.179")
    monkeypatch.setattr(
        capture,
        "probe_dumpcap_interface",
        lambda identifier, capture_filter: {"attempted": True, "ready": True, "identifier": identifier},
    )

    result = capture.inspect_capture_environment("tcp port 9227")

    assert result["capture_backend"] == "dumpcap"
    assert result["backend_ready"] is True


def test_frozen_app_parser_accepts_collector_watch_arguments() -> None:
    args = build_app_parser().parse_args(
        [
            "--collector-watch",
            "--session",
            "session",
            "--backend",
            "scapy",
            "--interfaces",
            r"\Device\NPF_TEST",
            "--interface-names",
            "Meta",
        ]
    )

    assert args.collector_watch is True
    assert args.backend == "scapy"
    assert args.interfaces == [r"\Device\NPF_TEST"]


def test_capture_manager_retries_initial_start(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manager = capture.CaptureManager(
        tmp_path,
        "scapy",
        ["test-interface"],
        ["Test"],
        tmp_path / "events.jsonl",
        "tcp port 9227",
    )
    attempts = 0

    def start_attempt() -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise OSError("temporary failure")

    monkeypatch.setattr(manager, "_start_attempt", start_attempt)
    monkeypatch.setattr(manager, "_stop_attempt", lambda: None)
    monkeypatch.setattr(capture.time, "sleep", lambda _seconds: None)

    manager.start()

    assert attempts == 3
    assert manager.retry_count == 2
    assert manager.failed is False


def test_capture_ring_is_global_across_attempts(tmp_path: Path) -> None:
    manager = capture.CaptureManager(
        tmp_path,
        "dumpcap",
        ["1"],
        ["Test"],
        tmp_path / "events.jsonl",
        "tcp port 9227",
    )
    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    for index in range(capture.CAPTURE_RING_FILES + 2):
        path = pcap_dir / f"game-9227-segment-{index + 1:04d}.pcapng"
        path.write_bytes(bytes([index]))

    manager._enforce_capture_ring()

    files = sorted(pcap_dir.glob("*.pcapng"))
    assert len(files) == capture.CAPTURE_RING_FILES
    assert [path.name for path in files] == [
        "game-9227-segment-0003.pcapng",
        "game-9227-segment-0004.pcapng",
    ]


def test_scapy_writer_open_is_atomic_with_ring_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = capture.CaptureManager(
        tmp_path,
        "scapy",
        ["test-interface"],
        ["Test"],
        tmp_path / "events.jsonl",
        "tcp port 9227",
    )
    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    for index in range(capture.CAPTURE_RING_FILES):
        path = pcap_dir / f"game-9227-segment-{index + 1:04d}.pcapng"
        path.write_bytes(b"old")
        os.utime(path, (100 + index, 100 + index))
    manager.segment = capture.CAPTURE_RING_FILES

    writer_created = threading.Event()
    allow_writer = threading.Event()
    ring_started = threading.Event()
    ring_finished = threading.Event()
    errors: list[BaseException] = []

    class PausingWriter:
        header_present = True

        def __init__(self, raw_path: str) -> None:
            self.path = Path(raw_path)
            self.path.touch()
            os.utime(self.path, (1, 1))
            writer_created.set()
            if not allow_writer.wait(2):
                raise TimeoutError("test did not release writer creation")

        def close(self) -> None:
            pass

    monkeypatch.setattr("scapy.utils.PcapNgWriter", PausingWriter)

    def open_writer() -> None:
        try:
            manager._open_scapy_writer()
        except BaseException as error:
            errors.append(error)

    def enforce_ring() -> None:
        ring_started.set()
        try:
            manager._enforce_capture_ring()
        except BaseException as error:
            errors.append(error)
        finally:
            ring_finished.set()

    writer_thread = threading.Thread(target=open_writer)
    writer_thread.start()
    assert writer_created.wait(1)
    ring_thread = threading.Thread(target=enforce_ring)
    ring_thread.start()
    assert ring_started.wait(1)
    assert not ring_finished.wait(0.05)

    allow_writer.set()
    writer_thread.join(2)
    ring_thread.join(2)

    assert not writer_thread.is_alive()
    assert not ring_thread.is_alive()
    assert errors == []
    assert manager.current_capture_path is not None
    assert manager.current_capture_path.is_file()
    assert len(list(pcap_dir.glob("*.pcapng"))) == capture.CAPTURE_RING_FILES


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    padding = b"\x00" * (-len(body) % 4)
    padded_body = body + padding
    block_length = 12 + len(padded_body)
    return (
        struct.pack("<II", block_type, block_length)
        + padded_body
        + struct.pack("<I", block_length)
    )


def test_dumpcap_requires_a_real_pcapng_packet_block(tmp_path: Path) -> None:
    manager = capture.CaptureManager(
        tmp_path,
        "dumpcap",
        ["1"],
        ["Test"],
        tmp_path / "events.jsonl",
        "tcp port 9227 or udp port 9227",
    )
    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    capture_path = pcap_dir / "game-9227-segment-0001.pcapng"
    section_header = _pcapng_block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
    )
    interface_description = _pcapng_block(
        0x00000001,
        struct.pack("<HHI", 1, 0, 65535),
    )
    capture_path.write_bytes(section_header + interface_description)

    manager._refresh_dumpcap_activity()

    assert manager.capture_has_packets is False

    interface_statistics = _pcapng_block(
        0x00000005,
        struct.pack("<III", 0, 0, 0),
    )
    with capture_path.open("ab") as stream:
        stream.write(interface_statistics)
    manager._refresh_dumpcap_activity()

    assert manager.capture_has_packets is False

    enhanced_packet = _pcapng_block(
        0x00000006,
        struct.pack("<IIIII", 0, 0, 0, 4, 4) + b"test",
    )
    with capture_path.open("ab") as stream:
        stream.write(enhanced_packet)
    manager._refresh_dumpcap_activity()

    assert manager.capture_has_packets is True


def test_collector_status_publishes_capture_feedback_fields(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session_dir = tmp_path / "session"
    runtime_dir = tmp_path / "runtime"
    instance = collector.Collector.__new__(collector.Collector)
    instance.session_dir = session_dir
    instance.status_path = session_dir / "status.json"
    instance.collector_create_time = 123.5
    instance.tracked_pids = {321}
    instance.observed_flows = set()
    instance.capture_backend = "scapy"
    instance.interface_names = ["Test"]
    instance.capture = SimpleNamespace(
        packet_count=7,
        capture_has_packets=True,
        is_running=True,
    )
    monkeypatch.setattr(collector, "RUNTIME_DIR", runtime_dir)

    instance._write_status("capturing")

    status = json.loads(instance.status_path.read_text(encoding="utf-8"))
    active = json.loads((runtime_dir / "active.json").read_text(encoding="utf-8"))
    assert status["capture_packets"] == 7
    assert status["capture_packet_count_exact"] is True
    assert status["capture_has_packets"] is True
    assert status["capture_ready"] is True
    assert active == status


def test_scapy_stop_is_bounded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manager = capture.CaptureManager(
        tmp_path,
        "scapy",
        ["test-interface"],
        ["Test"],
        tmp_path / "events.jsonl",
        "tcp port 9227",
    )

    class StuckThread:
        def is_alive(self) -> bool:
            return True

        def join(self, timeout: float | None = None) -> None:
            assert timeout == 3

    class StuckSniffer:
        thread = StuckThread()
        stop_cb = object()

        def stop(self, join: bool = True) -> None:
            assert join is False

    manager.sniffer = StuckSniffer()
    manager.stop()

    assert manager.failed is True
    assert manager.last_error == "Scapy capture thread did not stop within 3 seconds"
    events = [
        json.loads(line)
        for line in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    event_types = [event["type"] for event in events]
    assert "capture_stop_timeout" in event_types
    assert "capture_stop_incomplete" in event_types
    assert "capture_stopped" not in event_types


def test_scapy_writer_error_is_not_reported_as_success(tmp_path: Path) -> None:
    manager = capture.CaptureManager(
        tmp_path,
        "scapy",
        ["test-interface"],
        ["Test"],
        tmp_path / "events.jsonl",
        "tcp port 9227",
    )

    class EndedThread:
        def is_alive(self) -> bool:
            return False

    class EndedSniffer:
        thread = EndedThread()

    manager.sniffer = EndedSniffer()
    manager._scapy_error = "ValueError: writer closed"
    manager.stop()

    assert manager.failed is True
    assert manager.last_error == "ValueError: writer closed"


def test_frozen_start_background_uses_same_executable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sessions = tmp_path / "sessions"
    runtime = tmp_path / "runtime"
    captured_arguments: list[str] = []

    class FakeProcess:
        pid = 1234

        def poll(self) -> None:
            return None

    def fake_popen(arguments: list[str], **_kwargs: object) -> FakeProcess:
        captured_arguments.extend(arguments)
        return FakeProcess()

    monkeypatch.setattr(collector, "_active_collector", lambda: None)
    monkeypatch.setattr(
        collector,
        "preflight",
        lambda: {
            "ready": True,
            "capture_backend": "scapy",
            "selected_interface_ids": [r"\Device\NPF_TEST"],
            "selected_interface_names": ["Meta"],
        },
    )
    monkeypatch.setattr(collector, "SESSIONS_DIR", sessions)
    monkeypatch.setattr(collector, "RUNTIME_DIR", runtime)
    monkeypatch.setattr(collector.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        collector,
        "read_json",
        lambda _path, default=None: {
            "state": "waiting_for_game",
            "capture_ready": True,
        },
    )

    collector.start_background()

    assert captured_arguments[:2] == [sys.executable, "--collector-watch"]
    assert "--backend" in captured_arguments
    assert r"\Device\NPF_TEST" in captured_arguments


def test_collector_start_lock_rejects_parallel_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(collector, "RUNTIME_DIR", tmp_path / "runtime")

    with collector._collector_start_lock():
        with pytest.raises(RuntimeError, match="already in progress"):
            with collector._collector_start_lock():
                pass


def test_start_timeout_stops_child_and_marks_session_failed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sessions = tmp_path / "sessions"
    runtime = tmp_path / "runtime"

    class FakeProcess:
        pid = 4321
        returncode = None
        waited = False

        def poll(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            self.waited = True
            return 0

        def terminate(self) -> None:
            raise AssertionError("clean stop request should be attempted first")

        def kill(self) -> None:
            raise AssertionError("clean stop request should be attempted first")

    process = FakeProcess()
    monotonic_values = iter((0.0, 11.0))
    monkeypatch.setattr(collector, "_active_collector", lambda: None)
    monkeypatch.setattr(
        collector,
        "preflight",
        lambda: {
            "ready": True,
            "capture_backend": "scapy",
            "selected_interface_ids": [r"\Device\NPF_TEST"],
            "selected_interface_names": ["Meta"],
        },
    )
    monkeypatch.setattr(collector, "SESSIONS_DIR", sessions)
    monkeypatch.setattr(collector, "RUNTIME_DIR", runtime)
    monkeypatch.setattr(collector.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(collector.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(collector, "read_json", lambda _path, default=None: default)

    with pytest.raises(TimeoutError, match="child stopped"):
        collector.start_background()

    session = next(sessions.iterdir())
    assert process.waited is True
    assert (session / "stop.request").is_file()
    status_path = session / "status.json"
    assert status_path.is_file()
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status["state"] == "failed"
    assert status["collector_pid"] == process.pid
