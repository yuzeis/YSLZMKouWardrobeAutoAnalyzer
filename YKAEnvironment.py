"""Windows capture prerequisites and guided Npcap installation.

Scapy is the only Python dependency used by the native capture/decoder path.
Npcap is the only required system component.  The free Npcap installer is
intentionally launched visibly; this module never passes ``/S``.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from urllib.parse import urlparse
import urllib.request
from pathlib import Path
from typing import Any, Callable


NPCAP_VERSION = "1.88"
NPCAP_INSTALLER_URL = "https://npcap.com/dist/npcap-1.88.exe"
NPCAP_DOWNLOAD_HOST = "npcap.com"


def _npcap_candidates() -> tuple[Path, ...]:
    windows = Path(os.environ.get("WINDIR", r"C:\Windows"))
    return (
        windows / "System32" / "Npcap" / "wpcap.dll",
        windows / "System32" / "Npcap" / "Packet.dll",
        windows / "System32" / "wpcap.dll",
        windows / "System32" / "Packet.dll",
        windows / "SysWOW64" / "Npcap" / "wpcap.dll",
        windows / "SysWOW64" / "Npcap" / "Packet.dll",
    )


def npcap_installed() -> bool:
    """Return whether a usable Npcap DLL is visible to this process."""
    if os.name != "nt":
        return False
    if any(path.is_file() for path in _npcap_candidates()):
        return True
    return bool(ctypes.util.find_library("wpcap"))


def scapy_installed() -> bool:
    return importlib.util.find_spec("scapy") is not None


def inspect_environment() -> dict[str, Any]:
    """Check the minimal components, Npcap service, interface, and live probe."""
    from YKACapture import inspect_capture_environment
    from YKACore import GAME_CAPTURE_FILTER

    capture = inspect_capture_environment(GAME_CAPTURE_FILTER)
    components = capture.get("required_components", {})
    npcap_component = components.get("npcap", {}) if isinstance(components, dict) else {}
    scapy_component = components.get("scapy", {}) if isinstance(components, dict) else {}
    required = {
        "npcap": bool(isinstance(npcap_component, dict) and npcap_component.get("installed")),
        "scapy": bool(isinstance(scapy_component, dict) and scapy_component.get("installed")),
    }
    missing = [name for name, installed in required.items() if not installed]
    ready = bool(
        capture.get("backend_ready")
        and isinstance(npcap_component, dict)
        and npcap_component.get("ready")
        and isinstance(scapy_component, dict)
        and scapy_component.get("ready")
    )
    return {
        "ready": ready,
        "backend": "Scapy/Npcap" if ready else "不可用",
        "required": required,
        "missing": missing,
        "npcap": {
            **(npcap_component if isinstance(npcap_component, dict) else {}),
            "version": "unknown" if required["npcap"] else None,
            "available_installer_version": NPCAP_VERSION,
        },
        "scapy": scapy_component,
        "optional": {"tshark": False, "mergecap": False},
        "capture_probe": capture.get("capture_probe", {}),
        "selected_interface_names": capture.get("selected_interface_names", []),
        "messages": (
            ["环境满足 Scapy 原生采集所需条件"]
            if ready
            else (
                [f"缺少必要组件：{', '.join(missing)}"]
                if missing
                else ["必要组件已安装，但 Npcap 服务、网卡或抓包探测未就绪"]
            )
        ),
    }


check_environment = inspect_environment


def install_scapy() -> None:
    """Install Scapy for source-mode runs using the active Python runtime."""
    if scapy_installed():
        return
    if getattr(sys, "frozen", False):
        raise RuntimeError("程序包缺少内置 Scapy，请重新获取完整发布包")
    completed = subprocess.run(
        [sys.executable, "-m", "pip", "install", "scapy>=2.7,<3"],
        check=False,
        text=True,
        capture_output=True,
        timeout=300,
    )
    if completed.returncode != 0 or not scapy_installed():
        detail = (completed.stderr or completed.stdout or "pip 安装失败").strip()
        raise RuntimeError(detail)


def _verify_authenticode(path: Path) -> tuple[bool, str]:
    """Verify a downloaded installer with Windows Authenticode.

    Verification fails closed on Windows when PowerShell cannot report a valid
    signature.
    """
    if os.name != "nt":
        return False, "Authenticode 仅支持 Windows"
    command = (
        "$s = Get-AuthenticodeSignature -LiteralPath "
        + "'" + str(path).replace("'", "''") + "'; "
        "$o = [ordered]@{Status=$s.Status;Subject=''}; "
        "if ($s.SignerCertificate) {$o.Subject=$s.SignerCertificate.Subject}; "
        "$o | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"无法验证 Authenticode：{error}"
    if result.returncode != 0:
        return False, (result.stderr or "Authenticode 检查失败").strip()
    try:
        payload = json.loads(result.stdout or "{}")
    except ValueError:
        return False, "Authenticode 输出无法解析"
    status = str(payload.get("Status", ""))
    subject = str(payload.get("Subject", ""))
    subject_lower = subject.lower()
    signer_ok = "nmap" in subject_lower or "insecure.com" in subject_lower
    if status.lower() == "valid" and signer_ok:
        return True, subject
    return False, f"签名无效或签名者不受信任：{status} {subject}".strip()


def download_npcap_installer(
    destination: Path | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> Path:
    """Download the official installer after validating the HTTPS host.

    Environment checks never download; callers invoke this after user action.
    """
    parsed = urlparse(NPCAP_INSTALLER_URL)
    if parsed.scheme.lower() != "https" or parsed.hostname != NPCAP_DOWNLOAD_HOST:
        raise ValueError("Npcap 下载地址不是受信任的 HTTPS 官方地址")
    target_dir = Path(destination) if destination is not None else Path(tempfile.gettempdir()) / "YKAAuto"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"npcap-{NPCAP_VERSION}.exe"
    partial = target.with_suffix(target.suffix + ".part")
    request = urllib.request.Request(NPCAP_INSTALLER_URL, headers={"User-Agent": "YKA-Scanner"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as stream:
            total = int(response.headers.get("Content-Length") or 0)
            done = 0
            while True:
                chunk = response.read(1024 * 128)
                if not chunk:
                    break
                stream.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
        valid, detail = _verify_authenticode(partial)
        if not valid:
            raise RuntimeError(detail)
        os.replace(partial, target)
    except Exception:
        try:
            partial.unlink()
        except OSError:
            pass
        raise
    return target


def launch_npcap_installer(installer: Path, wait: bool = True) -> int | None:
    """Launch the installer visibly with elevation; never use silent flags."""
    installer = Path(installer).resolve()
    if not installer.is_file() or installer.suffix.lower() != ".exe":
        raise FileNotFoundError(installer)
    if os.name != "nt":
        raise OSError("Npcap 引导安装仅支持 Windows")
    class ShellExecuteInfo(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong),
            ("fMask", ctypes.c_ulong),
            ("hwnd", ctypes.c_void_p),
            ("lpVerb", ctypes.c_wchar_p),
            ("lpFile", ctypes.c_wchar_p),
            ("lpParameters", ctypes.c_wchar_p),
            ("lpDirectory", ctypes.c_wchar_p),
            ("nShow", ctypes.c_int),
            ("hInstApp", ctypes.c_void_p),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.c_wchar_p),
            ("hkeyClass", ctypes.c_void_p),
            ("dwHotKey", ctypes.c_ulong),
            ("hIcon", ctypes.c_void_p),
            ("hProcess", ctypes.c_void_p),
        ]

    info = ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = str(installer)
    info.lpDirectory = str(installer.parent)
    info.nShow = 1  # SW_SHOWNORMAL: visible installer UI
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        raise OSError("ShellExecuteExW 启动失败")
    if not wait or not info.hProcess:
        return None
    ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
    exit_code = ctypes.c_ulong()
    ctypes.windll.kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code))
    ctypes.windll.kernel32.CloseHandle(info.hProcess)
    return int(exit_code.value)


def guide_install_npcap(
    destination: Path | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> Path:
    """Download, verify, and visibly launch the official free installer."""
    installer = download_npcap_installer(destination, progress)
    launch_npcap_installer(installer, wait=True)
    return installer
