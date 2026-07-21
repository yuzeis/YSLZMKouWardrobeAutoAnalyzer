from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

import psutil

from YKACore import (
    CAPTURE_FILESIZE_KIB,
    CAPTURE_MAX_RETRIES,
    CAPTURE_RING_FILES,
    DUMPCAP_PATH,
    RUNTIME_DIR,
)
from YKACore import append_jsonl, now_iso


CAPTURE_BACKEND_DUMPCAP = "dumpcap"
CAPTURE_BACKEND_SCAPY = "scapy"
CAPTURE_BACKEND_ENV = "YKA_CAPTURE_BACKEND"
CAPTURE_INTERFACE_ENV = "YKA_CAPTURE_INTERFACE"
# Keep the old names readable for existing local setups, but do not expose
# them in the new UI or documentation.
_LEGACY_CAPTURE_BACKEND_ENV = "YSLZM_CAPTURE_BACKEND"
_LEGACY_CAPTURE_INTERFACE_ENV = "YSLZM_CAPTURE_INTERFACE"
PCAPNG_SECTION_HEADER = b"\x0a\x0d\x0d\x0a"
PCAPNG_PACKET_BLOCK_TYPES = {0x00000002, 0x00000003, 0x00000006}

_VIRTUAL_INTERFACE_TOKENS = (
    "bluetooth",
    "docker",
    "loopback",
    "meta tunnel",
    "tailscale",
    "tap-windows",
    "virtualbox",
    "vmware",
    "vpn",
    "wan miniport",
    "veth",
    "vethernet",
    "wsl",
)


def _pcapng_contains_packet(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return False

    offset = 0
    byte_order: str | None = None
    while offset + 12 <= len(data):
        block_type_bytes = data[offset : offset + 4]
        if block_type_bytes == PCAPNG_SECTION_HEADER:
            byte_order_magic = data[offset + 8 : offset + 12]
            if byte_order_magic == b"\x4d\x3c\x2b\x1a":
                byte_order = "little"
            elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
                byte_order = "big"
            else:
                return False
        elif byte_order is None:
            return False

        block_type = int.from_bytes(block_type_bytes, byte_order)
        block_length = int.from_bytes(
            data[offset + 4 : offset + 8], byte_order
        )
        if block_length < 12 or block_length % 4:
            return False
        block_end = offset + block_length
        if block_end > len(data):
            return False
        trailing_length = int.from_bytes(
            data[block_end - 4 : block_end], byte_order
        )
        if trailing_length != block_length:
            return False
        if block_type in PCAPNG_PACKET_BLOCK_TYPES:
            return True
        offset = block_end
    return False
_PHYSICAL_INTERFACE_HINTS = (
    "ethernet",
    "wi-fi",
    "wifi",
    "wlan",
    "以太网",
    "无线",
)


def _run_text(
    arguments: list[str], timeout: float = 15.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        shell=False,
    )


def _npcap_paths() -> list[Path]:
    windows = Path(os.environ.get("WINDIR", r"C:\Windows"))
    return [
        windows / "System32" / "Npcap" / "wpcap.dll",
        windows / "System32" / "Npcap" / "Packet.dll",
        windows / "SysWOW64" / "Npcap" / "wpcap.dll",
        windows / "SysWOW64" / "Npcap" / "Packet.dll",
        windows / "System32" / "wpcap.dll",
    ]


def inspect_npcap() -> dict[str, Any]:
    detected_paths = [str(path) for path in _npcap_paths() if path.is_file()]
    service_status = "unknown"
    if os.name == "nt":
        try:
            service_status = psutil.win_service_get("npcap").status()
        except (AttributeError, OSError, psutil.Error):
            service_status = "not_found"
    return {
        "installed": bool(detected_paths),
        "detected_paths": detected_paths,
        "service_status": service_status,
    }


def _ipv4_addresses(name: str, fallback: str = "") -> list[str]:
    values = [
        item.address
        for item in psutil.net_if_addrs().get(name, ())
        if item.family == socket.AF_INET and item.address
    ]
    if fallback and fallback not in values:
        try:
            ipaddress.ip_address(fallback)
        except ValueError:
            pass
        else:
            values.append(fallback)
    return values


def _is_virtual_interface(name: str, description: str, device: str) -> bool:
    haystack = f"{name} {description} {device}".casefold()
    return any(token in haystack for token in _VIRTUAL_INTERFACE_TOKENS)


def _is_usable_ipv4(address: str) -> bool:
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return False
    return bool(
        value.version == 4
        and not value.is_loopback
        and not value.is_link_local
        and not value.is_unspecified
    )


def inspect_scapy() -> dict[str, Any]:
    status: dict[str, Any] = {
        "installed": False,
        "version": None,
        "use_pcap": False,
        "ready": False,
        "error": None,
    }
    try:
        import scapy  # type: ignore[import-untyped]
        from scapy.all import conf  # type: ignore[import-untyped]

        status["installed"] = True
        status["version"] = str(getattr(scapy, "__version__", "unknown"))
        status["use_pcap"] = bool(conf.use_pcap)
        status["ready"] = bool(conf.use_pcap)
    except Exception as error:
        status["error"] = f"{type(error).__name__}: {error}"
    return status


def list_scapy_interfaces() -> list[dict[str, Any]]:
    if os.name != "nt":
        return []
    try:
        from scapy.all import conf  # type: ignore[import-untyped]
    except Exception:
        return []

    stats = psutil.net_if_stats()
    interfaces: list[dict[str, Any]] = []
    for raw in conf.ifaces.values():
        name = str(getattr(raw, "name", "") or "")
        description = str(getattr(raw, "description", "") or "")
        device = str(getattr(raw, "network_name", "") or name)
        addresses = _ipv4_addresses(name, str(getattr(raw, "ip", "") or ""))
        interface_stats = stats.get(name)
        is_up = bool(interface_stats.isup) if interface_stats else bool(addresses)
        if not name or not device or not is_up or not addresses:
            continue
        try:
            index = int(getattr(raw, "index", 0) or 0)
        except (TypeError, ValueError):
            index = 0
        interfaces.append(
            {
                "index": index,
                "identifier": device,
                "device": device,
                "name": name,
                "description": description,
                "addresses": addresses,
                "backend": CAPTURE_BACKEND_SCAPY,
                "is_virtual": _is_virtual_interface(name, description, device),
            }
        )
    return sorted(
        interfaces,
        key=lambda item: (
            str(item["name"]).casefold(),
            str(item["identifier"]).casefold(),
        ),
    )


def list_dumpcap_interfaces() -> list[dict[str, Any]]:
    if not DUMPCAP_PATH.is_file():
        return []
    result = _run_text([str(DUMPCAP_PATH), "-D"])
    if result.returncode != 0:
        return []
    pattern = re.compile(r"^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?$")
    interfaces: list[dict[str, Any]] = []
    stats = psutil.net_if_stats()
    for line in result.stdout.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        name = (match.group(3) or match.group(2)).strip()
        device = match.group(2)
        addresses = _ipv4_addresses(name)
        interface_stats = stats.get(name)
        interfaces.append(
            {
                "index": int(match.group(1)),
                "identifier": str(int(match.group(1))),
                "device": device,
                "name": name,
                "description": name,
                "addresses": addresses,
                "backend": CAPTURE_BACKEND_DUMPCAP,
                "is_virtual": _is_virtual_interface(name, name, device),
                "is_up": bool(interface_stats.isup) if interface_stats else None,
            }
        )
    return interfaces


def default_route_ipv4() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            return str(probe.getsockname()[0])
    except OSError:
        return None


def select_capture_interfaces(
    interfaces: list[dict[str, Any]],
    *,
    requested_interface: str | None = None,
    route_ipv4: str | None = None,
) -> tuple[list[dict[str, Any]], str]:
    if not interfaces:
        return [], "no_interfaces"

    active = [item for item in interfaces if item.get("is_up") is not False]

    requested = (requested_interface or "").strip()
    if requested:
        requested_folded = requested.casefold()
        for item in interfaces:
            candidates = {
                str(item.get("identifier", "")).casefold(),
                str(item.get("device", "")).casefold(),
                str(item.get("name", "")).casefold(),
                str(item.get("description", "")).casefold(),
            }
            if requested_folded in candidates:
                if item.get("is_up") is False:
                    return [], "requested_interface_down"
                return [item], "requested_interface"
        return [], "requested_interface_not_found"

    route = route_ipv4 or default_route_ipv4()
    if route:
        for item in active:
            if route in item.get("addresses", []):
                return [item], "default_route_ipv4"

    physical = [
        item
        for item in active
        if not item.get("is_virtual")
        and any(_is_usable_ipv4(value) for value in item.get("addresses", []))
    ]
    if physical:
        physical.sort(
            key=lambda item: (
                not any(
                    hint in f"{item.get('name', '')} {item.get('description', '')}".casefold()
                    for hint in _PHYSICAL_INTERFACE_HINTS
                ),
                str(item.get("name", "")).casefold(),
            )
        )
        return [physical[0]], "physical_ipv4_fallback"

    usable = [
        item
        for item in active
        if any(_is_usable_ipv4(value) for value in item.get("addresses", []))
    ]
    if usable:
        return [usable[0]], "usable_ipv4_fallback"
    return [], "no_active_ipv4_interface"


def probe_scapy_interface(identifier: str, capture_filter: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "attempted": True,
        "ready": False,
        "identifier": identifier,
        "error": None,
    }
    capture_socket: Any = None
    try:
        from scapy.all import ETH_P_ALL  # type: ignore[import-untyped]
        from scapy.interfaces import resolve_iface  # type: ignore[import-untyped]

        interface = resolve_iface(identifier)
        capture_socket = interface.l2listen()(
            type=ETH_P_ALL,
            iface=interface,
            filter=capture_filter,
        )
        result["ready"] = True
        result["name"] = str(getattr(interface, "name", identifier))
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if capture_socket is not None:
            try:
                capture_socket.close()
            except Exception:
                pass
    return result


def probe_dumpcap_interface(identifier: str, capture_filter: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "attempted": True,
        "ready": False,
        "identifier": identifier,
        "error": None,
    }
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="dumpcap-probe-",
            suffix=".pcapng",
            dir=RUNTIME_DIR,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
        completed = _run_text(
            [
                str(DUMPCAP_PATH),
                "-i",
                identifier,
                "-f",
                capture_filter,
                "-a",
                "duration:0.2",
                "-w",
                str(temporary_path),
            ],
            timeout=5.0,
        )
        result["ready"] = completed.returncode == 0
        if completed.returncode != 0:
            error = (completed.stderr or completed.stdout).strip()
            result["error"] = error or f"dumpcap exited with code {completed.returncode}"
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if temporary_path is not None and temporary_path.is_file():
            temporary_path.unlink(missing_ok=True)
    return result


def inspect_capture_environment(
    capture_filter: str,
    force_backend: str | None = None,
) -> dict[str, Any]:
    requested_backend = (
        force_backend
        or os.environ.get(CAPTURE_BACKEND_ENV)
        or os.environ.get(_LEGACY_CAPTURE_BACKEND_ENV, "")
    ).strip().lower()
    if requested_backend not in {"", CAPTURE_BACKEND_DUMPCAP, CAPTURE_BACKEND_SCAPY}:
        requested_backend = "invalid"

    npcap = inspect_npcap()
    scapy = inspect_scapy()
    scapy["ready"] = bool(
        scapy.get("ready") and npcap.get("installed") and os.name == "nt"
    )
    dumpcap_ready = DUMPCAP_PATH.is_file()

    candidate_backends: list[str] = []
    if requested_backend == CAPTURE_BACKEND_SCAPY:
        if scapy["ready"]:
            candidate_backends.append(CAPTURE_BACKEND_SCAPY)
    elif requested_backend == CAPTURE_BACKEND_DUMPCAP:
        if dumpcap_ready:
            candidate_backends.append(CAPTURE_BACKEND_DUMPCAP)
    elif requested_backend != "invalid":
        if scapy["ready"]:
            candidate_backends.append(CAPTURE_BACKEND_SCAPY)
        # Automatic mode is intentionally Scapy+Npcap only.  dumpcap remains
        # available as an explicit diagnostic backend via YKA_CAPTURE_BACKEND.

    backend: str | None = None
    interfaces: list[dict[str, Any]] = []
    selected: list[dict[str, Any]] = []
    selection_reason = "no_capture_backend"
    capture_probe: dict[str, Any] = {"attempted": False, "ready": False}
    backend_attempts: list[dict[str, Any]] = []
    route_ipv4 = default_route_ipv4()
    requested_interface = os.environ.get(CAPTURE_INTERFACE_ENV)
    if requested_interface is None:
        requested_interface = os.environ.get(_LEGACY_CAPTURE_INTERFACE_ENV)
    for candidate in candidate_backends:
        candidate_interfaces = (
            list_scapy_interfaces()
            if candidate == CAPTURE_BACKEND_SCAPY
            else list_dumpcap_interfaces()
        )
        candidate_selected, candidate_reason = select_capture_interfaces(
            candidate_interfaces,
            requested_interface=requested_interface,
            route_ipv4=route_ipv4,
        )
        candidate_probe: dict[str, Any] = {
            "attempted": False,
            "ready": bool(candidate_selected),
        }
        if candidate_selected:
            identifier = str(candidate_selected[0]["identifier"])
            if candidate == CAPTURE_BACKEND_SCAPY:
                candidate_probe = probe_scapy_interface(identifier, capture_filter)
            else:
                candidate_probe = probe_dumpcap_interface(identifier, capture_filter)
        backend_attempts.append(
            {
                "backend": candidate,
                "selected_interface_ids": [
                    str(item["identifier"]) for item in candidate_selected
                ],
                "selection_reason": candidate_reason,
                "capture_probe": candidate_probe,
            }
        )
        interfaces = candidate_interfaces
        selected = candidate_selected
        selection_reason = candidate_reason
        capture_probe = candidate_probe
        if candidate_selected and candidate_probe.get("ready"):
            backend = candidate
            break

    backend_ready = bool(backend and selected and capture_probe.get("ready"))
    npcap_installed = bool(npcap.get("installed"))
    npcap_ready = bool(
        npcap_installed
        and (npcap.get("service_status") == "running" or backend_ready)
    )
    scapy_installed = bool(scapy.get("installed"))
    scapy_ready = bool(
        scapy_installed and backend == CAPTURE_BACKEND_SCAPY and backend_ready
    )
    return {
        "requested_backend": requested_backend or "auto",
        "capture_backend": backend,
        "npcap": npcap,
        "scapy": scapy,
        "interfaces": interfaces,
        "selected_interfaces": selected,
        "selected_interface_indexes": [item.get("index") for item in selected],
        "selected_interface_ids": [str(item["identifier"]) for item in selected],
        "selected_interface_names": [str(item["name"]) for item in selected],
        "selection_reason": selection_reason,
        "default_route_ipv4": route_ipv4,
        "capture_probe": capture_probe,
        "backend_attempts": backend_attempts,
        "backend_ready": backend_ready,
        "required_components": {
            "npcap": {
                "required": True,
                "installed": npcap_installed,
                "service_status": npcap.get("service_status"),
                "ready": npcap_ready,
            },
            "scapy": {
                "required": True,
                "installed": scapy_installed,
                "ready": scapy_ready,
            },
            "tshark": {"required": False, "ready": False},
            "mergecap": {"required": False, "ready": False},
        },
    }


class CaptureManager:
    def __init__(
        self,
        session_dir: Path,
        backend: str,
        interface_ids: list[str],
        interface_names: list[str],
        event_log: Path,
        capture_filter: str,
    ) -> None:
        if backend not in {CAPTURE_BACKEND_DUMPCAP, CAPTURE_BACKEND_SCAPY}:
            raise ValueError(f"unsupported capture backend: {backend}")
        self.session_dir = session_dir
        self.backend = backend
        self.interface_ids = interface_ids
        self.interface_names = interface_names
        self.event_log = event_log
        self.capture_filter = capture_filter
        self._capture_state_lock = threading.RLock()
        self.process: subprocess.Popen[bytes] | None = None
        self.log_stream: Any = None
        self.sniffer: Any = None
        self.writer: Any = None
        self.current_capture_path: Path | None = None
        self.current_file_packet_count = 0
        self.capture_files: deque[Path] = deque()
        self.packet_count = 0
        self.capture_has_packets = False
        self.segment = 0
        self.retry_count = 0
        self.retry_due = 0.0
        self.failed = False
        self.stopping = False
        self.last_error: str | None = None
        self._scapy_started: Any = None
        self._scapy_error: str | None = None

    @property
    def is_running(self) -> bool:
        if self.backend == CAPTURE_BACKEND_DUMPCAP:
            return self.process is not None and self.process.poll() is None
        thread = getattr(self.sniffer, "thread", None)
        return bool(
            self.sniffer is not None
            and thread is not None
            and thread.is_alive()
            and self._scapy_error is None
        )

    def _next_capture_path(self, suffix: str) -> Path:
        self.segment += 1
        pcap_dir = self.session_dir / "pcap"
        pcap_dir.mkdir(parents=True, exist_ok=True)
        return pcap_dir / f"game-9227-segment-{self.segment:04d}.{suffix}"

    def _enforce_capture_ring(self) -> None:
        with self._capture_state_lock:
            self._enforce_capture_ring_locked()

    def _enforce_capture_ring_locked(self) -> None:
        pcap_dir = self.session_dir / "pcap"
        if not pcap_dir.is_dir():
            return

        def file_order(path: Path) -> tuple[int, str]:
            try:
                modified = path.stat().st_mtime_ns
            except OSError:
                modified = 0
            return modified, path.name

        files = sorted(
            (
                path
                for path in pcap_dir.glob("game-9227-segment-*.pcapng")
                if path.is_file()
            ),
            key=file_order,
        )
        excess = len(files) - CAPTURE_RING_FILES
        if excess <= 0:
            return
        current = self.current_capture_path.resolve() if self.current_capture_path else None
        current_active = self.is_running or self.writer is not None
        for old_path in files:
            if excess <= 0:
                break
            resolved = old_path.resolve()
            if resolved.parent != pcap_dir.resolve():
                raise RuntimeError("capture ring path escaped the session directory")
            if current is not None and resolved == current and current_active:
                continue
            try:
                old_path.unlink(missing_ok=True)
            except PermissionError:
                continue
            excess -= 1

    def _dumpcap_capture_files(self) -> list[Path]:
        pcap_dir = self.session_dir / "pcap"
        if not pcap_dir.is_dir():
            return []
        return sorted(
            path
            for path in pcap_dir.glob("game-9227-segment-*.pcapng")
            if path.is_file()
        )

    def _refresh_dumpcap_activity(self) -> None:
        if self.backend != CAPTURE_BACKEND_DUMPCAP or self.capture_has_packets:
            return
        for path in self._dumpcap_capture_files():
            if _pcapng_contains_packet(path):
                self.capture_has_packets = True
                return

    def _log_starting(self) -> None:
        append_jsonl(
            self.event_log,
            {
                "time": now_iso(),
                "type": "capture_starting",
                "backend": self.backend,
                "interfaces": self.interface_ids,
                "interface_names": self.interface_names,
                "capture_filter": self.capture_filter,
                "retry_count": self.retry_count,
            },
        )

    def _start_dumpcap(self) -> None:
        pcap_path = self._next_capture_path("pcapng")
        log_path = pcap_path.with_suffix(".dumpcap.log")
        arguments = [str(DUMPCAP_PATH)]
        for identifier in self.interface_ids:
            arguments.extend(["-i", identifier, "-f", self.capture_filter])
        arguments.extend(
            [
                "-s",
                "0",
                "-b",
                f"filesize:{CAPTURE_FILESIZE_KIB}",
                "-b",
                f"files:{CAPTURE_RING_FILES}",
                "-w",
                str(pcap_path),
            ]
        )
        self.log_stream = log_path.open("ab")
        self.process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=self.log_stream,
            stderr=subprocess.STDOUT,
            cwd=self.session_dir,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        time.sleep(0.35)
        if self.process.poll() is not None:
            returncode = self.process.returncode
            self._stop_attempt()
            raise RuntimeError(f"dumpcap exited during startup with code {returncode}")
        files = sorted(pcap_path.parent.glob(f"{pcap_path.stem}*.pcapng"))
        if not files:
            self._stop_attempt()
            raise RuntimeError("dumpcap did not create a capture file")
        with self._capture_state_lock:
            self.current_capture_path = files[-1]
            self._enforce_capture_ring_locked()
        append_jsonl(
            self.event_log,
            {
                "time": now_iso(),
                "type": "capture_ready",
                "backend": self.backend,
                "files": [str(path) for path in files],
            },
        )

    def _open_scapy_writer(self) -> Path:
        from scapy.utils import PcapNgWriter  # type: ignore[import-untyped]

        with self._capture_state_lock:
            path = self._next_capture_path("pcapng")
            writer = PcapNgWriter(str(path))
            self.writer = writer
            self.current_capture_path = path
            self.current_file_packet_count = 0
            self.capture_files.append(path)
            while len(self.capture_files) > CAPTURE_RING_FILES:
                old_path = self.capture_files.popleft()
                expected_parent = (self.session_dir / "pcap").resolve()
                if old_path.resolve().parent != expected_parent:
                    raise RuntimeError(
                        "capture rotation path escaped the session directory"
                    )
                if old_path.name.startswith("game-9227-segment-"):
                    old_path.unlink(missing_ok=True)
            self._enforce_capture_ring_locked()
            return path

    def _rotate_scapy_writer_if_needed(self) -> None:
        with self._capture_state_lock:
            path = self.current_capture_path
            if path is None or not path.is_file():
                return
            if path.stat().st_size < CAPTURE_FILESIZE_KIB * 1024:
                return
            if self.writer is None:
                raise RuntimeError("Scapy capture writer is unavailable")
            self.writer.close()
            path = self._open_scapy_writer()
        append_jsonl(
            self.event_log,
            {
                "time": now_iso(),
                "type": "capture_rotated",
                "backend": self.backend,
                "file": str(path),
            },
        )

    def _on_scapy_packet(self, packet: Any) -> None:
        if self.stopping or self._scapy_error is not None:
            return
        try:
            self.writer.write(packet)
            self.writer.flush()
            self.packet_count += 1
            self.capture_has_packets = True
            self.current_file_packet_count += 1
            self._rotate_scapy_writer_if_needed()
        except Exception as error:
            self._scapy_error = f"{type(error).__name__}: {error}"

    def _start_scapy(self) -> None:
        # Register Windows link-layer decoders in a fresh PyInstaller child.
        from scapy.layers import inet as _scapy_inet  # noqa: F401
        from scapy.layers import inet6 as _scapy_inet6  # noqa: F401
        from scapy.layers import l2 as _scapy_l2  # noqa: F401
        from scapy.sendrecv import AsyncSniffer  # type: ignore[import-untyped]

        first_path = self._open_scapy_writer()
        self._scapy_error = None
        self._scapy_started = threading.Event()
        interface_value: str | list[str]
        if len(self.interface_ids) == 1:
            interface_value = self.interface_ids[0]
        else:
            interface_value = self.interface_ids
        self.sniffer = AsyncSniffer(
            iface=interface_value,
            prn=self._on_scapy_packet,
            filter=self.capture_filter,
            store=False,
            started_callback=self._scapy_started.set,
        )
        self.sniffer.start()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if self._scapy_started.wait(0.05):
                break
            exception = getattr(self.sniffer, "exception", None)
            thread = getattr(self.sniffer, "thread", None)
            if exception is not None:
                self._scapy_error = f"{type(exception).__name__}: {exception}"
                break
            if thread is not None and not thread.is_alive():
                self._scapy_error = "Scapy capture thread exited during startup"
                break
        if not self._scapy_started.is_set():
            error = self._scapy_error or "Scapy capture did not become ready within 3 seconds"
            self._stop_attempt()
            raise RuntimeError(error)
        append_jsonl(
            self.event_log,
            {
                "time": now_iso(),
                "type": "capture_ready",
                "backend": self.backend,
                "files": [str(first_path)],
            },
        )

    def _start_attempt(self) -> None:
        if not self.interface_ids:
            raise RuntimeError("no capture interfaces selected")
        self._log_starting()
        if self.backend == CAPTURE_BACKEND_DUMPCAP:
            self._start_dumpcap()
        else:
            self._start_scapy()

    def start(self) -> None:
        self.stopping = False
        self.failed = False
        self.last_error = None
        self.retry_due = 0.0
        while True:
            try:
                self._start_attempt()
                return
            except Exception as error:
                self._stop_attempt()
                message = f"{type(error).__name__}: {error}"
                self.last_error = message
                retry = not self.failed and self.retry_count < CAPTURE_MAX_RETRIES
                append_jsonl(
                    self.event_log,
                    {
                        "time": now_iso(),
                        "type": "capture_start_failed",
                        "backend": self.backend,
                        "error": message,
                        "retry": retry,
                    },
                )
                if not retry:
                    self.failed = True
                    raise RuntimeError(
                        f"{self.backend} capture failed to start after "
                        f"{self.retry_count + 1} attempts: {message}"
                    ) from error
                self.retry_count += 1
                time.sleep(0.5)

    def _capture_failure(self, error: str) -> None:
        self.last_error = error
        append_jsonl(
            self.event_log,
            {
                "time": now_iso(),
                "type": "capture_exited",
                "backend": self.backend,
                "error": error,
                "retry": self.retry_count < CAPTURE_MAX_RETRIES,
            },
        )
        self._stop_attempt()
        if not self.failed and self.retry_count < CAPTURE_MAX_RETRIES:
            self.retry_count += 1
            self.retry_due = time.monotonic() + 2.0
        else:
            self.failed = True
            append_jsonl(
                self.event_log,
                {
                    "time": now_iso(),
                    "type": "capture_failed_permanently",
                    "backend": self.backend,
                    "error": error,
                },
            )

    def poll(self) -> None:
        if self.stopping or self.failed:
            return
        self._enforce_capture_ring()
        self._refresh_dumpcap_activity()
        if self.retry_due:
            if time.monotonic() < self.retry_due:
                return
            self.retry_due = 0.0
            try:
                self._start_attempt()
            except Exception as error:
                self._capture_failure(f"{type(error).__name__}: {error}")
            return
        if self.is_running:
            return
        if self.backend == CAPTURE_BACKEND_DUMPCAP and self.process is not None:
            self._capture_failure(f"dumpcap exited with code {self.process.returncode}")
            return
        if self.backend == CAPTURE_BACKEND_SCAPY and self.sniffer is not None:
            exception = getattr(self.sniffer, "exception", None)
            error = self._scapy_error
            if error is None and exception is not None:
                error = f"{type(exception).__name__}: {exception}"
            self._capture_failure(error or "Scapy capture stopped unexpectedly")

    def _stop_attempt(self) -> bool:
        if self.backend == CAPTURE_BACKEND_DUMPCAP:
            self._refresh_dumpcap_activity()
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            self._refresh_dumpcap_activity()
            self.process = None
            if self.log_stream is not None:
                self.log_stream.close()
                self.log_stream = None
            return True

        sniffer = self.sniffer
        thread_still_alive = False
        if sniffer is not None:
            thread = getattr(sniffer, "thread", None)
            try:
                if thread is not None and thread.is_alive() and hasattr(sniffer, "stop_cb"):
                    sniffer.stop(join=False)
                    thread.join(timeout=3)
                elif thread is not None and thread.is_alive():
                    thread.join(timeout=3)
            except Exception as error:
                if self._scapy_error is None:
                    self._scapy_error = f"{type(error).__name__}: {error}"
            if thread is not None and thread.is_alive():
                thread_still_alive = True
                self.failed = True
                self._scapy_error = "Scapy capture thread did not stop within 3 seconds"
                self.last_error = self._scapy_error
                append_jsonl(
                    self.event_log,
                    {
                        "time": now_iso(),
                        "type": "capture_stop_timeout",
                        "backend": self.backend,
                        "error": self._scapy_error,
                    },
                )
        if thread_still_alive:
            return False
        self.sniffer = None
        with self._capture_state_lock:
            if self.writer is not None:
                if (
                    self.current_file_packet_count == 0
                    and not getattr(self.writer, "header_present", False)
                ):
                    self.writer.f.close()
                else:
                    self.writer.close()
                self.writer = None
            path = self.current_capture_path
            if (
                path is not None
                and path.is_file()
                and self.current_file_packet_count == 0
            ):
                expected_parent = (self.session_dir / "pcap").resolve()
                if path.resolve().parent == expected_parent:
                    path.unlink(missing_ok=True)
                    try:
                        self.capture_files.remove(path)
                    except ValueError:
                        pass
        return True

    def stop(self) -> None:
        self.stopping = True
        self.retry_due = 0.0
        stopped = self._stop_attempt()
        if self._scapy_error is not None:
            self.failed = True
            self.last_error = self._scapy_error
        append_jsonl(
            self.event_log,
            {
                "time": now_iso(),
                "type": "capture_stopped" if stopped else "capture_stop_incomplete",
                "backend": self.backend,
                "packet_count": self.packet_count,
                "capture_has_packets": self.capture_has_packets,
            },
        )
