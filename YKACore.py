from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any


SOURCE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else SOURCE_ROOT
)

_CUSTOM_DATA_DIR = os.environ.get("YKA_DATA_DIR", "").strip()
if _CUSTOM_DATA_DIR:
    DATA_ROOT = Path(_CUSTOM_DATA_DIR).expanduser()
else:
    DATA_ROOT = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "YKAAuto"
RUNTIME_DIR = DATA_ROOT / "runtime"
SESSIONS_DIR = DATA_ROOT / "sessions"

WIRESHARK_DIR = Path(
    os.environ.get("YKA_WIRESHARK_DIR", r"C:\Program Files\Wireshark")
)
DUMPCAP_PATH = WIRESHARK_DIR / "dumpcap.exe"

_CUSTOM_LAUNCHER = os.environ.get("YKA_LAUNCHER", "").strip()
KNOWN_LAUNCHERS = tuple(
    path
    for path in (
        Path(_CUSTOM_LAUNCHER) if _CUSTOM_LAUNCHER else None,
        Path(r"C:\Program Files\LifeMakeoverLauncher_ob_zh_20\yslzmLoader.exe"),
        Path(r"C:\Program Files\LifeMakeoverLauncher_ob_zh_20\yslzmLoader1.exe"),
        Path(
            r"C:\Program Files\LifeMakeoverLauncher_ob_zh_20\Launcher\yslzmLauncher.exe"
        ),
        Path(r"C:\Program Files\LifeMakeoverLauncher_ob_zh_504\yslzmLoader.exe"),
        Path(r"C:\Program Files\LifeMakeoverLauncher_ob_zh_504\yslzmLoader1.exe"),
        Path(
            r"C:\Program Files\LifeMakeoverLauncher_ob_zh_504\Launcher\yslzmLauncher.exe"
        ),
    )
    if path is not None
)

ANCHOR_PROCESS_NAMES = {
    "yslzmloader.exe",
    "yslzmloader1.exe",
    "yslzmlauncher.exe",
}

GAME_NAME_HINTS = (
    "yslzm",
    "lifemakeover",
    "life_makeover",
    "archosaur",
    "azure.exe",
    "azure-win64-shipping.exe",
)

POLL_INTERVAL_SECONDS = 0.5
OPEN_FILE_POLL_SECONDS = 5.0
GAME_SERVICE_PORT = 9227
CAPTURE_FILESIZE_KIB = 32768
CAPTURE_RING_FILES = 2
CAPTURE_RETAIN_UNTIL_EXPORT = True
CAPTURE_MAX_RETRIES = 2
CAPTURE_DRAIN_SECONDS = 2.0


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(20):
            try:
                os.replace(temporary, path)
                return
            except OSError as error:
                retryable = isinstance(error, PermissionError) or getattr(
                    error, "winerror", None
                ) in {5, 32}
                if not retryable or attempt == 19:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
        stream.write("\n")


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default
