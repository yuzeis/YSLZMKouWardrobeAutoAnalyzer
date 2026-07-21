from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import ctypes
import configparser
from contextlib import contextmanager
from datetime import datetime
from ctypes import wintypes
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import psutil

from YKACore import (
    ANCHOR_PROCESS_NAMES,
    CAPTURE_DRAIN_SECONDS,
    CAPTURE_FILESIZE_KIB,
    CAPTURE_MAX_RETRIES,
    CAPTURE_RETAIN_UNTIL_EXPORT,
    GAME_SERVICE_PORT,
    GAME_NAME_HINTS,
    KNOWN_LAUNCHERS,
    OPEN_FILE_POLL_SECONDS,
    POLL_INTERVAL_SECONDS,
    PROJECT_ROOT,
    RUNTIME_DIR,
    SESSIONS_DIR,
)
from YKACapture import CaptureManager, inspect_capture_environment
from YKACore import append_jsonl, atomic_write_json, now_iso, read_json


@dataclass(frozen=True, order=True)
class Flow:
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int

    @property
    def key(self) -> str:
        return (
            f"{self.protocol}_{self.local_ip}_{self.local_port}_"
            f"{self.remote_ip}_{self.remote_port}"
        )


def discover_game_executables() -> list[str]:
    return [
        str(path)
        for root in discover_game_roots()
        for path in (
            root / "Azure.exe",
            root / "Azure" / "Binaries" / "Win64" / "Azure-Win64-Shipping.exe",
        )
        if path.is_file()
    ]


def discover_game_roots() -> list[Path]:
    local_app_data = Path(os.environ.get("LOCALAPPDATA", ""))
    if not local_app_data.is_dir():
        return []
    roots: list[Path] = []
    for launcher_data in sorted(local_app_data.glob("LifeMakeoverLauncher_ob_zh_*")):
        settings = launcher_data / "settings.ini"
        if not settings.is_file():
            continue
        parser = configparser.ConfigParser()
        try:
            parser.read(settings, encoding="utf-8")
            raw_path = parser.get("General", "game_install_path", fallback="")
        except (configparser.Error, OSError):
            continue
        if not raw_path:
            continue
        game_root = Path(raw_path.replace("/", os.sep)).resolve()
        if game_root.is_dir():
            roots.append(game_root)
    return sorted(set(roots))


def _relevant_open_file(path: Path, game_roots: list[Path]) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    if not any(resolved == root or root in resolved.parents for root in game_roots):
        return False
    lowered = str(resolved).lower()
    if any(
        token in lowered
        for token in ("\\chat", "socialspace", "\\voice", "\\screenshots")
    ):
        return False
    return resolved.suffix.lower() in {
        ".bin",
        ".cfg",
        ".dat",
        ".db",
        ".ini",
        ".json",
        ".lua",
        ".sqlite",
        ".xml",
    }


def socket_owner_probe() -> dict[str, Any]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = int(server.getsockname()[1])
        connections = psutil.net_connections(kind="tcp")
        visible = any(
            connection.pid == os.getpid()
            and (_address(connection.laddr) or ("", 0))[1] == port
            for connection in connections
        )
        missing_pid_count = sum(connection.pid is None for connection in connections)
        return {
            "visible": visible,
            "connection_count": len(connections),
            "missing_pid_count": missing_pid_count,
        }
    except (OSError, psutil.Error) as error:
        return {"visible": False, "error": repr(error)}
    finally:
        server.close()


def preflight() -> dict[str, Any]:
    capture_filter = f"tcp port {GAME_SERVICE_PORT} or udp port {GAME_SERVICE_PORT}"
    capture = inspect_capture_environment(capture_filter)
    scapy_status = capture.get("scapy", {})
    analysis_ready = bool(
        isinstance(scapy_status, dict) and scapy_status.get("installed")
    )
    launchers = [str(path) for path in KNOWN_LAUNCHERS if path.exists()]
    game_roots = discover_game_roots()
    game_executables = discover_game_executables()
    owner_probe = socket_owner_probe()
    result = {
        "checked_at": now_iso(),
        "python": sys.version.split()[0],
        "psutil": psutil.__version__,
        "analysis_backend": "scapy-native",
        "known_launchers": launchers,
        "game_executables": game_executables,
        "game_roots": [str(path) for path in game_roots],
        "socket_owner_probe": owner_probe,
        "analysis_ready": analysis_ready,
        **capture,
        "ready": bool(
            (launchers or game_executables)
            and capture["backend_ready"]
            and analysis_ready
        ),
    }
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write_json(RUNTIME_DIR / "preflight.json", result)
    return result


class _ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def _snapshot_processes() -> dict[int, dict[str, Any]]:
    if os.name != "nt":
        result: dict[int, dict[str, Any]] = {}
        for process in psutil.process_iter(attrs=["pid", "name"]):
            try:
                pid = int(process.info["pid"])
                result[pid] = {
                    "pid": pid,
                    "ppid": process.ppid(),
                    "name": str(process.info.get("name") or ""),
                    "exe": "",
                    "create_time": 0.0,
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
        return result

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    create_snapshot.restype = wintypes.HANDLE
    process_first = kernel32.Process32FirstW
    process_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    process_first.restype = wintypes.BOOL
    process_next = kernel32.Process32NextW
    process_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    process_next.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    snapshot = create_snapshot(0x00000002, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    result: dict[int, dict[str, Any]] = {}
    entry = _ProcessEntry32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        success = bool(process_first(snapshot, ctypes.byref(entry)))
        while success:
            pid = int(entry.th32ProcessID)
            result[pid] = {
                "pid": pid,
                "ppid": int(entry.th32ParentProcessID),
                "name": str(entry.szExeFile),
                "exe": "",
                "create_time": 0.0,
            }
            success = bool(process_next(snapshot, ctypes.byref(entry)))
    finally:
        close_handle(snapshot)
    return result


def _detailed_process_info(base: dict[str, Any]) -> dict[str, Any]:
    info = dict(base)
    try:
        process = psutil.Process(int(base["pid"]))
        info["exe"] = process.exe()
        info["create_time"] = process.create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        pass
    return info


def _is_anchor(info: dict[str, Any]) -> bool:
    return info["name"].lower() in ANCHOR_PROCESS_NAMES


def _has_game_hint(info: dict[str, Any]) -> bool:
    haystack = f"{info['name']} {info['exe']}".lower()
    return any(hint in haystack for hint in GAME_NAME_HINTS)


def _address(value: Any) -> tuple[str, int] | None:
    if not value:
        return None
    if hasattr(value, "ip") and hasattr(value, "port"):
        return str(value.ip), int(value.port)
    if isinstance(value, tuple) and len(value) >= 2:
        return str(value[0]), int(value[1])
    return None


def _flow_from_connection(connection: Any) -> Flow | None:
    local = _address(connection.laddr)
    remote = _address(connection.raddr)
    if not local or not remote:
        return None
    protocol = "tcp" if connection.type == socket.SOCK_STREAM else "udp"
    return Flow(protocol, local[0], local[1], remote[0], remote[1])


class Collector:
    def __init__(
        self,
        session_dir: Path,
        capture_backend: str,
        interface_ids: list[str],
        interface_names: list[str],
    ) -> None:
        self.session_dir = session_dir
        self.capture_backend = capture_backend
        self.interface_ids = interface_ids
        self.interface_names = interface_names
        try:
            self.collector_create_time = psutil.Process(os.getpid()).create_time()
        except (psutil.Error, OSError):
            self.collector_create_time = 0.0
        self.event_log = session_dir / "events.jsonl"
        self.status_path = session_dir / "status.json"
        self.stop_path = session_dir / "stop.request"
        self.tracked_pids: set[int] = set()
        self.tracked_names: dict[int, str] = {}
        self.tracked_create_times: dict[int, float] = {}
        self.anchor_pids: set[int] = set()
        self.logged_processes: set[tuple[int, str]] = set()
        self.logged_flows: set[tuple[int, Flow]] = set()
        self.observed_flows: set[Flow] = set()
        self.logged_files: dict[tuple[int, str], tuple[int | None, float | None]] = {}
        self.last_open_file_poll = 0.0
        self.game_roots = discover_game_roots()
        self.capture = CaptureManager(
            session_dir,
            capture_backend,
            interface_ids,
            interface_names,
            self.event_log,
            f"tcp port {GAME_SERVICE_PORT} or udp port {GAME_SERVICE_PORT}",
        )

    def _write_status(self, state: str, **extra: Any) -> None:
        status = {
            "state": state,
            "updated_at": now_iso(),
            "collector_pid": os.getpid(),
            "collector_create_time": self.collector_create_time,
            "session_dir": str(self.session_dir),
            "tracked_pids": sorted(self.tracked_pids),
            "flow_count": len(self.observed_flows),
            "capture_backend": self.capture_backend,
            "capture_interfaces": self.interface_names,
            "capture_packets": self.capture.packet_count,
            "capture_packet_count_exact": self.capture_backend == "scapy",
            "capture_has_packets": self.capture.capture_has_packets,
            "capture_ready": self.capture.is_running,
            **extra,
        }
        atomic_write_json(self.status_path, status)
        atomic_write_json(RUNTIME_DIR / "active.json", status)

    def _discover_processes(self) -> dict[int, dict[str, Any]]:
        processes = _snapshot_processes()

        for pid in tuple(self.tracked_pids):
            current = processes.get(pid)
            expected_name = self.tracked_names.get(pid, "")
            identity_changed = bool(
                current and expected_name and current["name"].lower() != expected_name
            )
            if current and not identity_changed:
                expected_time = self.tracked_create_times.get(pid, 0.0)
                if expected_time:
                    try:
                        current_time = psutil.Process(pid).create_time()
                        identity_changed = abs(current_time - expected_time) > 0.001
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                        pass
            if identity_changed:
                self.tracked_pids.discard(pid)
                self.anchor_pids.discard(pid)
                self.tracked_names.pop(pid, None)
                self.tracked_create_times.pop(pid, None)

        changed = True
        while changed:
            changed = False
            for pid, info in processes.items():
                if pid in self.tracked_pids:
                    continue
                anchor = _is_anchor(info)
                hinted = _has_game_hint(info)
                descendant = info["ppid"] in self.tracked_pids
                if anchor or hinted or descendant:
                    detailed = _detailed_process_info(info)
                    processes[pid] = detailed
                    info = detailed
                    self.tracked_pids.add(pid)
                    self.tracked_names[pid] = info["name"].lower()
                    self.tracked_create_times[pid] = float(info.get("create_time") or 0.0)
                    if anchor:
                        self.anchor_pids.add(pid)
                    changed = True

        for pid in sorted(self.tracked_pids):
            info = processes.get(pid)
            if not info:
                continue
            identity = (pid, info["name"].lower())
            if identity in self.logged_processes:
                continue
            append_jsonl(
                self.event_log,
                {
                    "time": now_iso(),
                    "type": "target_process",
                    **info,
                    "anchor": pid in self.anchor_pids,
                },
            )
            self.logged_processes.add(identity)
        return processes

    def _discover_connections(self) -> None:
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as error:
            append_jsonl(
                self.event_log,
                {"time": now_iso(), "type": "connection_error", "error": str(error)},
            )
            return
        for connection in connections:
            if connection.pid not in self.tracked_pids:
                continue
            flow = _flow_from_connection(connection)
            if not flow:
                continue
            key = (int(connection.pid), flow)
            if key not in self.logged_flows:
                append_jsonl(
                    self.event_log,
                    {
                        "time": now_iso(),
                        "type": "network_flow",
                        "pid": int(connection.pid),
                        "state": str(connection.status),
                        **asdict(flow),
                    },
                )
                self.logged_flows.add(key)
            self.observed_flows.add(flow)

    def _discover_open_files(self) -> None:
        now = time.monotonic()
        if now - self.last_open_file_poll < OPEN_FILE_POLL_SECONDS:
            return
        self.last_open_file_poll = now
        for pid in sorted(self.tracked_pids):
            try:
                files = psutil.Process(pid).open_files()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
            for item in files:
                file_path = Path(item.path)
                if not _relevant_open_file(file_path, self.game_roots):
                    continue
                path = str(file_path)
                key = (pid, path.lower())
                try:
                    stat = Path(path).stat()
                    size = stat.st_size
                    modified = stat.st_mtime
                except OSError:
                    size = None
                    modified = None
                observation = (size, modified)
                previous = self.logged_files.get(key)
                if previous == observation:
                    continue
                append_jsonl(
                    self.event_log,
                    {
                        "time": now_iso(),
                        "type": "open_file",
                        "pid": pid,
                        "path": path,
                        "size": size,
                        "modified_epoch": modified,
                        "change": "opened" if previous is None else "modified",
                    },
                )
                self.logged_files[key] = observation

    def run(self) -> int:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        metadata = {
            "started_at": now_iso(),
            "collector_pid": os.getpid(),
            "collector_create_time": self.collector_create_time,
            "capture_backend": self.capture_backend,
            "interface_ids": self.interface_ids,
            "interface_names": self.interface_names,
            "mode": "passive-read-only",
            "capture_filter": self.capture.capture_filter,
            "capture_segment_limit_bytes": CAPTURE_FILESIZE_KIB * 1024,
            "capture_retention": (
                "until_wechat_export"
                if CAPTURE_RETAIN_UNTIL_EXPORT
                else "bounded_ring"
            ),
            "capture_retry_limit": CAPTURE_MAX_RETRIES,
            "capture_drain_seconds": CAPTURE_DRAIN_SECONDS,
            "raw_evidence": "stored locally only; never uploaded by this tool",
            "constraints": [
                "no gacha actions",
                "no request injection or replay",
                "no WeChat access",
                "report generation only",
            ],
        }
        atomic_write_json(self.session_dir / "session.json", metadata)
        append_jsonl(self.event_log, {"time": now_iso(), "type": "collector_started"})
        self._write_status("starting_capture")
        try:
            self.capture.start()
            self._write_status("waiting_for_game", capture_ready=True)
            while not self.stop_path.exists():
                self._discover_processes()
                self._discover_connections()
                self._discover_open_files()
                self.capture.poll()
                if self.capture.failed:
                    raise RuntimeError(
                        f"{self.capture_backend} capture failed after all retry attempts"
                    )
                state = "capturing" if self.tracked_pids else "waiting_for_game"
                self._write_status(state)
                time.sleep(POLL_INTERVAL_SECONDS)
            append_jsonl(
                self.event_log,
                {
                    "time": now_iso(),
                    "type": "capture_draining",
                    "seconds": CAPTURE_DRAIN_SECONDS,
                },
            )
            self._write_status("draining_capture")
            drain_deadline = time.monotonic() + CAPTURE_DRAIN_SECONDS
            while time.monotonic() < drain_deadline:
                self.capture.poll()
                if self.capture.failed:
                    raise RuntimeError(
                        f"{self.capture_backend} capture failed while draining capture"
                    )
                remaining = drain_deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(POLL_INTERVAL_SECONDS, remaining))
        except KeyboardInterrupt:
            append_jsonl(self.event_log, {"time": now_iso(), "type": "collector_interrupted"})
        except Exception as error:
            append_jsonl(
                self.event_log,
                {"time": now_iso(), "type": "collector_error", "error": repr(error)},
            )
            self._write_status("failed", error=repr(error))
            return 1
        finally:
            self.capture.stop()
        if self.capture.failed:
            error = self.capture.last_error or "capture did not stop cleanly"
            append_jsonl(
                self.event_log,
                {"time": now_iso(), "type": "collector_error", "error": error},
            )
            self._write_status("failed", error=error)
            return 1
        atomic_write_json(
            self.session_dir / "flows.json",
            [asdict(flow) for flow in sorted(self.observed_flows)],
        )
        append_jsonl(self.event_log, {"time": now_iso(), "type": "collector_stopped"})
        self._write_status("stopped", analysis_pending=True)
        return 0


def _active_collector() -> dict[str, Any] | None:
    active = read_json(RUNTIME_DIR / "active.json")
    if not isinstance(active, dict):
        return None
    pid = active.get("collector_pid")
    if not isinstance(pid, int) or not psutil.pid_exists(pid):
        return None
    expected_create_time = active.get("collector_create_time")
    if not isinstance(expected_create_time, (int, float)) or not expected_create_time:
        return None
    try:
        current_create_time = psutil.Process(pid).create_time()
    except (psutil.Error, OSError):
        return None
    if abs(current_create_time - float(expected_create_time)) > 0.001:
        return None
    return active


def current_capture_status() -> dict[str, Any]:
    active = read_json(RUNTIME_DIR / "active.json")
    if not isinstance(active, dict):
        return {"state": "not_started"}
    state = str(active.get("state") or "not_started")
    if state in {
        "starting_capture",
        "waiting_for_game",
        "capturing",
        "draining_capture",
        "analyzing",
        "stop_pending",
    } and _active_collector() is None:
        return {"state": "not_started"}
    return active


@contextmanager
def _collector_start_lock() -> Any:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    stream = (RUNTIME_DIR / "collector-start.lock").open("a+b")
    locked = False
    try:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError("another collector start is already in progress") from error
        locked = True
        yield
    finally:
        if locked:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


def start_background() -> dict[str, Any]:
    with _collector_start_lock():
        return _start_background_locked()


def _start_background_locked() -> dict[str, Any]:
    active = _active_collector()
    if active and active.get("state") not in {"stopped", "failed"}:
        raise RuntimeError(f"collector already active: pid={active['collector_pid']}")

    check = preflight()
    if not check["ready"]:
        raise RuntimeError("preflight failed; inspect runtime/preflight.json")
    session_id = datetime.now().strftime("%Y%m%dT%H%M%S-%f")
    session_dir = SESSIONS_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=False)
    log_stream = (session_dir / "collector.log").open("ab")
    common_arguments = [
        "--session",
        str(session_dir),
        "--backend",
        str(check["capture_backend"]),
        "--interfaces",
        *[str(identifier) for identifier in check["selected_interface_ids"]],
        "--interface-names",
        *[str(name) for name in check["selected_interface_names"]],
    ]
    if getattr(sys, "frozen", False):
        arguments = [sys.executable, "--collector-watch", *common_arguments]
    else:
        main_path = PROJECT_ROOT / "YKAApp.py"
        arguments = [sys.executable, str(main_path), "--collector-watch", *common_arguments]
    creationflags = 0
    creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0)
    creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        process = subprocess.Popen(
            arguments,
            cwd=PROJECT_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
            shell=False,
            creationflags=creationflags,
            close_fds=True,
        )
    except Exception as error:
        status = {
            "state": "failed",
            "updated_at": now_iso(),
            "session_dir": str(session_dir),
            "error": f"collector process failed to start: {error!r}",
        }
        atomic_write_json(session_dir / "status.json", status)
        atomic_write_json(RUNTIME_DIR / "active.json", status)
        raise
    finally:
        log_stream.close()
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        status = read_json(session_dir / "status.json")
        if isinstance(status, dict):
            if status.get("state") in {"waiting_for_game", "capturing"} and status.get(
                "capture_ready"
            ):
                return status
            if status.get("state") == "failed":
                raise RuntimeError(status.get("error", "collector failed during startup"))
        if process.poll() is not None:
            raise RuntimeError(
                f"collector exited with code {process.returncode}; session={session_dir}"
            )
        time.sleep(0.1)
    (session_dir / "stop.request").write_text(now_iso(), encoding="utf-8")
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    status = read_json(session_dir / "status.json", {})
    if not isinstance(status, dict) or status.get("state") not in {"stopped", "failed"}:
        status = {
            "state": "failed",
            "updated_at": now_iso(),
            "collector_pid": process.pid,
            "session_dir": str(session_dir),
            "error": "collector startup timed out and the child process was stopped",
        }
        atomic_write_json(session_dir / "status.json", status)
        atomic_write_json(RUNTIME_DIR / "active.json", status)
    raise TimeoutError(
        f"collector did not publish ready status within 10 seconds; "
        f"child stopped; session={session_dir}"
    )


def request_stop(timeout: float = 15.0) -> dict[str, Any]:
    active = read_json(RUNTIME_DIR / "active.json")
    if not isinstance(active, dict) or not active.get("session_dir"):
        return {"state": "not_running"}
    if active.get("state") in {"stopped", "failed"}:
        return active
    verified = _active_collector()
    if verified is None:
        return {"state": "stale_active_record"}
    active = verified
    session_dir = Path(active["session_dir"])
    try:
        session_dir = session_dir.resolve()
        sessions_root = SESSIONS_DIR.resolve()
    except OSError:
        return {"state": "invalid_active_session"}
    if session_dir == sessions_root or sessions_root not in session_dir.parents:
        return {"state": "invalid_active_session", "session_dir": str(session_dir)}
    (session_dir / "stop.request").write_text(now_iso(), encoding="utf-8")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = read_json(session_dir / "status.json", {})
        if status.get("state") in {"stopped", "failed"}:
            return status
        time.sleep(0.2)
    return read_json(session_dir / "status.json", {"state": "stop_pending"})


def run_watch(
    session: Path,
    backend: str,
    interfaces: list[str],
    interface_names: list[str],
) -> int:
    return Collector(
        session.resolve(),
        backend,
        interfaces,
        interface_names,
    ).run()
