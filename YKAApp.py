from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Callable

from PIL import Image, ImageTk

import YKATheme as ui_theme
from YKACompactCodec import (
    ArtifactError,
    ImportArtifacts,
    build_import_artifacts,
    load_catalog as load_compact_catalog,
)
from YKAQR import (
    QR_KINDS,
    QR_KIND_C1_BASE64,
    QR_KIND_COMPRESSED_JSON,
    QRCapacityError,
    QRMetadata,
    export_qr,
)
from YKATheme import (
    Banner,
    StatusBadge,
    autowrap,
    card,
    render_markdown,
    style_text_widget,
)
from YKAWechatImport import (
    ImportDataError,
    ImportResult,
    generate_import_code_from_report,
    load_pool_catalog,
    validate_import_code,
)
from YKACollector import (
    current_capture_status,
    preflight,
    request_stop,
    run_watch,
    start_background,
)
from YKACapture import inspect_npcap, inspect_scapy, list_scapy_interfaces
from YKACore import SESSIONS_DIR, now_iso
from YKAEnvironment import guide_install_npcap, install_scapy
from YKAReport import (
    build_live_coverage,
    build_session_report,
    cleanup_session_capture_files,
    persist_wechat_export,
)


APP_NAME = "YSLZMKouWardrobeAutoAnalyzer"
APP_VERSION = "ver1.0-beta1"
APP_CODENAME = "Gnadenfülle"
APP_TITLE = f"{APP_NAME} {APP_VERSION} - {APP_CODENAME}"
PROJECT_ROOT = Path(__file__).resolve().parent
RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))
POOL_CATALOG_PATH = RESOURCE_ROOT / "DatAnDict" / "YKAPoolCatalog.json"
COMPACT_CATALOG_PATH = RESOURCE_ROOT / "DatAnDict" / "YKACompactCatalog.json"
COMPACT_REGISTRY_PATH = RESOURCE_ROOT / "DatAnDict" / "YKACompactRegistry.json"
PROTOCOL_SPEC_PATH = RESOURCE_ROOT / "Docs" / "YKAProtocolSpec.md"
LICENSE_PATH = RESOURCE_ROOT / "LICENSE"
SOURCE_REPOSITORY_URL = (
    "https://github.com/yuzeis/YSLZMKouWardrobeAutoAnalyzer"
)
LIVE_ANALYSIS_INTERVAL_SECONDS = 2.0
LIVE_CAPTURE_STATES = frozenset({"waiting_for_game", "capturing"})

STATE_LABELS = {
    "not_started": "未开始",
    "starting_capture": "正在启动",
    "waiting_for_game": "等待游戏",
    "capturing": "正在采集",
    "draining_capture": "正在收尾",
    "analyzing": "正在生成报告文件",
    "stopped": "已停止",
    "failed": "失败",
    "stop_pending": "等待停止",
    "not_running": "未运行",
}
# 采集状态 -> 徽章颜色语义
STATE_SEMANTICS = {
    "not_started": "idle",
    "not_running": "idle",
    "starting_capture": "run",
    "waiting_for_game": "run",
    "capturing": "run",
    "draining_capture": "run",
    "analyzing": "run",
    "stop_pending": "run",
    "stopped": "ok",
    "failed": "error",
}
IMPORT_STATUS_LABELS = {
    0: "未抽齐",
    1: "有裙",
    2: "全齐",
    3: "扩裙",
    4: "全扩",
    5: "特姿/满色",
    6: "特姿/满色裙幻",
    7: "千幻",
    8: "想抽",
    9: "全齐裙幻",
    10: "全扩裙幻",
}


@dataclass(frozen=True)
class StartupNotice:
    title: str
    body: str
    semantic: str
    action: str | None = None


STARTUP_NOTICES = (
    StartupNotice(
        title="账号、封禁与法律风险提示",
        semantic="error",
        body=(
            "本工具通过只读方式分析《以闪亮之名》Windows 客户端产生的本地"
            "网络流量，并生成采集报告及导入数据。本工具不参与抽卡，不控制游戏，"
            "也不操作微信。\n\n"
            "使用第三方分析工具仍可能违反游戏、平台或相关服务的用户协议，并可能"
            "造成账号限制、封禁、数据异常或其他损失。使用者应自行确认其使用方式"
            "符合所在地法律法规及相关服务协议。\n\n"
            "本软件按“现状”提供。作者及贡献者不保证其适用性、准确性、持续可用性"
            "或不会触发游戏风控；在适用法律允许的最大范围内，不承担因使用或无法"
            "使用本软件产生的责任。\n\n"
            "点击“同意”表示你已阅读并理解上述风险，并决定自行承担使用后果。"
        ),
    ),
    StartupNotice(
        title="AGPL-3.0-only 开源许可与无担保声明",
        semantic="gold",
        action="license",
        body=(
            "Copyright (C) 2026 yuzeis and contributors\n\n"
            "本程序的自有源代码以 GNU Affero General Public License version 3 "
            "only 发布，SPDX 标识为 AGPL-3.0-only。\n\n"
            "你可以在遵守该许可证的前提下运行、研究、复制、修改和再发布本程序。"
            "发布修改版本或通过网络向他人提供修改版本的功能时，应履行 "
            "AGPL-3.0-only 规定的对应源代码及许可证义务。第三方组件仍分别适用"
            "其自身许可证。\n\n"
            "本程序按“原样”（AS IS）提供，不附带任何明示或默示担保。此处仅为"
            "摘要，完整且有法律效力的条款以程序随附的 LICENSE 文件为准。\n\n"
            "“同意”仅表示已经阅读本启动提示，不改变许可证依法授予的权利。"
        ),
    ),
    StartupNotice(
        title="永久免费、官方源码与侵权处理声明",
        semantic="ok",
        action="repository",
        body=(
            "本项目采用公开源代码的发布方式，官方发布版本绝对免费，不设置"
            "付费版、授权码、会员、捐赠解锁或收费功能。正式向公众发布时，"
            "与程序版本对应的完整源代码和 LICENSE 必须同步到以下唯一官方"
            "源码仓库：\n"
            f"{SOURCE_REPOSITORY_URL}\n\n"
            "如有人以作者或官方名义要求付款，请勿支付，并通过官方仓库核验来源。"
            "AGPL-3.0-only 允许第三方依法收费传播副本或提供服务；此类行为不代表"
            "作者或官方收费。\n\n"
            "如本项目内容被确认侵犯第三方合法权利，维护者将在收到可核验的权利"
            "通知后 12 小时内，下架或删除相关内容或版本，并配合后续处理。"
        ),
    ),
)


def _center_window(window: tk.Toplevel, width: int, height: int) -> None:
    window.update_idletasks()
    x = max((window.winfo_screenwidth() - width) // 2, 0)
    y = max((window.winfo_screenheight() - height) // 2, 0)
    window.geometry(f"{width}x{height}+{x}+{y}")


def _open_url(parent: tk.Misc, url: str, label: str) -> None:
    try:
        if not webbrowser.open_new_tab(url):
            raise OSError("系统没有接受打开请求")
    except Exception as error:
        messagebox.showerror(APP_NAME, f"{label}失败\n\n{error}", parent=parent)


def open_license(parent: tk.Misc) -> None:
    if not LICENSE_PATH.is_file():
        messagebox.showerror(
            APP_NAME,
            f"未找到许可证文件\n\n{LICENSE_PATH}",
            parent=parent,
        )
        return
    _open_url(parent, LICENSE_PATH.as_uri(), "打开许可证")


def open_source_repository(parent: tk.Misc) -> None:
    _open_url(parent, SOURCE_REPOSITORY_URL, "打开官方源码仓库")


def _show_startup_notice(
    root: tk.Tk,
    theme: ui_theme.Theme,
    notice: StartupNotice,
    index: int,
    total: int,
) -> bool:
    accepted = False
    window = tk.Toplevel(root)
    window.withdraw()
    window.title(f"{APP_NAME} - {notice.title}")
    window.configure(background=theme.colors["app_bg"])
    window.minsize(560, 390)

    def finish(result: bool) -> None:
        nonlocal accepted
        accepted = result
        try:
            window.grab_release()
        except tk.TclError:
            pass
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", lambda: finish(False))
    window.bind("<Escape>", lambda _event: finish(False))

    foreground, background, border = ui_theme.SEMANTIC[notice.semantic]
    header = tk.Frame(
        window,
        background=background,
        highlightthickness=1,
        highlightbackground=border,
    )
    header.pack(fill="x")
    tk.Label(
        header,
        text=f"{index} / {total}",
        background=background,
        foreground=foreground,
        font=theme.fonts["latin_small"],
    ).pack(anchor="w", padx=20, pady=(14, 2))
    tk.Label(
        header,
        text=notice.title,
        background=background,
        foreground=foreground,
        font=theme.fonts["title"],
        anchor="w",
    ).pack(fill="x", padx=20, pady=(0, 14))

    body = ScrolledText(window, wrap="word", height=16, undo=False)
    style_text_widget(body, theme, mono=False)
    body.pack(fill="both", expand=True, padx=20, pady=(16, 10))
    body.insert("1.0", notice.body)
    body.configure(state="disabled")

    if notice.action is not None:
        action_command = (
            (lambda: open_license(window))
            if notice.action == "license"
            else (lambda: open_source_repository(window))
        )
        action_text = (
            "查看完整许可证"
            if notice.action == "license"
            else "打开官方源码仓库"
        )
        ttk.Button(
            window,
            text=action_text,
            command=action_command,
            style="Secondary.TButton",
        ).pack(anchor="w", padx=20, pady=(0, 8))

    ttk.Separator(window, orient="horizontal").pack(fill="x")
    controls = ttk.Frame(window, padding=(20, 12))
    controls.pack(fill="x")
    exit_button = ttk.Button(
        controls,
        text="退出",
        command=lambda: finish(False),
        style="Secondary.TButton",
    )
    exit_button.pack(side="left")
    ttk.Button(
        controls,
        text="同意",
        command=lambda: finish(True),
        style="Primary.TButton",
    ).pack(side="right")

    _center_window(window, 640, 470)
    window.deiconify()
    window.wait_visibility()
    window.lift()
    window.grab_set()
    exit_button.focus_force()
    root.wait_window(window)
    return accepted


StartupNoticePresenter = Callable[
    [tk.Tk, ui_theme.Theme, StartupNotice, int, int],
    bool,
]


def show_startup_notices(
    root: tk.Tk,
    theme: ui_theme.Theme,
    *,
    presenter: StartupNoticePresenter | None = None,
) -> bool:
    show = presenter or _show_startup_notice
    total = len(STARTUP_NOTICES)
    for index, notice in enumerate(STARTUP_NOTICES, start=1):
        if not show(root, theme, notice, index, total):
            return False
    return True


def qr_error_text(kind: str, error: Exception) -> str:
    message = str(error)
    if isinstance(error, QRCapacityError) and kind == QR_KIND_COMPRESSED_JSON:
        return f"{message}；请切换 C1 Base64 或 C1 Base4096"
    return message


def qr_metadata_text(kind: str, metadata: QRMetadata) -> str:
    density = "；高密度" if metadata.high_density else ""
    guidance = (
        "；完整衣柜建议使用 C1 Base64 或 C1 Base4096"
        if kind == QR_KIND_COMPRESSED_JSON and metadata.high_density
        else ""
    )
    return (
        f"{metadata.characters} 字符 / {metadata.utf8_bytes} B；"
        f"QR v{metadata.version}-{metadata.error_correction}；"
        f"{metadata.pixels} x {metadata.pixels} px{density}{guidance}"
    )


def capture_traffic_feedback(status: dict[str, Any]) -> tuple[str, str, bool]:
    state = str(status.get("state") or "not_started")
    raw_packets = status.get("capture_packets")
    packets = raw_packets if type(raw_packets) is int and raw_packets >= 0 else 0
    has_packets = status.get("capture_has_packets") is True or packets > 0
    exact_count = status.get("capture_packet_count_exact") is True

    if has_packets:
        if exact_count and packets > 0:
            return "ok", f"已抓到 · {packets} 个 9227 端口包", True
        return "ok", "已抓到 · 检测到 9227 端口数据", True
    if state == "failed":
        return "error", "采集失败", False
    if state in {
        "starting_capture",
        "waiting_for_game",
        "capturing",
        "draining_capture",
        "stop_pending",
    }:
        return "run", "尚未抓到 · 等待 9227 游戏流量", False
    if state in {"analyzing", "stopped"}:
        return "warn", "未抓到 · 本次没有 9227 端口流量", False
    return "empty", "尚未开始", False


class ReporterApp:
    def __init__(
        self,
        root: tk.Tk,
        theme: ui_theme.Theme | None = None,
    ) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(ui_theme.DEFAULT_WINDOW)
        self.root.minsize(*ui_theme.MIN_WINDOW)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._events: queue.Queue[
            tuple[str, str, Any, Callable[[Any], None] | None]
        ] = queue.Queue()
        self._busy_count = 0
        self._last_state = ""
        self._last_capture_session = ""
        self._last_capture_hit = False
        self._active_session: Path | None = None
        self._current_report: dict[str, Any] | None = None
        self._report_revision = 0
        self._last_import_result: ImportResult | None = None
        self._last_raw_import_code: str | None = None
        self._last_import_artifacts: ImportArtifacts | None = None
        self._last_import_report_revision: int | None = None
        self._qr_source_image: Image.Image | None = None
        self._qr_preview_photo: ImageTk.PhotoImage | None = None
        self._qr_metadata: QRMetadata | None = None
        self._task_buttons: list[ttk.Button] = []
        self._environment_repair_prompted = False
        self._live_analysis_generation = 0
        self._live_analysis_inflight = False
        self._live_analysis_last_started = 0.0
        self._live_analysis_last_revision: tuple[tuple[str, int, int], ...] | None = None
        self._live_analysis_last_error = ""
        self._live_analysis_retry_count = 0
        self._live_decode_warning = ""
        self._live_browse_badges: dict[str, dict[str, Any]] = {}

        self.capture_state_var = tk.StringVar(value="未开始")
        self.session_var = tk.StringVar(value="-")
        self.environment_var = tk.StringVar(value="尚未检查")
        self.report_summary_var = tk.StringVar(value="尚未生成报告文件")
        self.import_summary_text = "尚未生成"
        self.target_image_width_var = tk.StringVar(value="261")
        self.qr_kind_var = tk.StringVar(value=QR_KIND_C1_BASE64)
        self.qr_meta_var = tk.StringVar(value="尚未生成")

        self.theme = theme or ui_theme.Theme(self.root)
        self._build_layout()
        self.root.after(100, self._drain_events)
        self.root.after(500, self._poll_collector_status)

    # ------------------------------------------------------------------ 布局
    def _build_layout(self) -> None:
        theme = self.theme
        sp = theme.space

        # 顶部标题栏：珍珠白底 + 香槟金细线
        header = ttk.Frame(self.root, style="Header.TFrame")
        header.pack(fill="x")
        head_row = ttk.Frame(header, style="Header.TFrame")
        head_row.pack(fill="x", padx=sp["lg"], pady=(sp["md"], sp["sm"]))
        head_row.columnconfigure(0, weight=1)
        title_group = ttk.Frame(head_row, style="Header.TFrame")
        title_group.grid(row=0, column=0, sticky="w")
        ttk.Label(title_group, text=APP_NAME, style="Title.TLabel").pack(side="left")
        tk.Frame(header, height=1, background=theme.colors["header_line"],
                 bd=0).pack(fill="x")

        # 标签页
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True,
                      padx=sp["page_pad"], pady=(sp["md"], sp["sm"]))
        self._notebook = notebook
        notebook.enable_traversal()  # Ctrl+Tab / Ctrl+Shift+Tab 切换标签页

        capture_report_tab = ttk.Frame(
            notebook, style="TFrame", padding=(0, sp["sm"], 0, 0)
        )
        import_tab = ttk.Frame(notebook, style="TFrame", padding=(0, sp["sm"], 0, 0))
        for tab, text in (
            (capture_report_tab, "采集与报告"),
            (import_tab, "微信导入码"),
        ):
            notebook.add(tab, text=text)

        capture_report_tab.columnconfigure(0, weight=1)
        capture_report_tab.rowconfigure(0, weight=1)
        panes = ttk.Panedwindow(capture_report_tab, orient="vertical")
        panes.grid(row=0, column=0, sticky="nsew")
        capture_panel = ttk.Frame(panes, style="TFrame")
        report_panel = ttk.Frame(panes, style="TFrame")
        panes.add(capture_panel, weight=3)
        panes.add(report_panel, weight=2)
        self._build_capture_tab(capture_panel)
        self._build_report_tab(report_panel)
        self._build_import_tab(import_tab)

        # 底部状态区：忙碌指示 + 版本
        footer = ttk.Frame(self.root, style="TFrame")
        footer.pack(fill="x", padx=sp["page_pad"], pady=(0, sp["sm"]))
        self.busy_var = tk.StringVar(value="就绪")
        ttk.Label(footer, textvariable=self.busy_var, style="Footer.TLabel").pack(
            side="left"
        )
        self._busy_bar = ttk.Progressbar(
            footer, mode="indeterminate", length=140,
            style="Busy.Horizontal.TProgressbar",
        )
        ttk.Label(
            footer,
            text=f"{APP_VERSION} / {APP_CODENAME}",
            style="FooterVersion.TLabel",
        ).pack(
            side="right"
        )
        legal_link = tk.Label(
            footer,
            text="开源许可",
            background=theme.colors["app_bg"],
            foreground=theme.colors["sky_text"],
            activeforeground=theme.colors["pink_press"],
            font=(*theme.fonts["small"], "underline"),
            cursor="hand2",
            takefocus=True,
        )
        legal_link.pack(side="right", padx=(0, sp["md"]))
        legal_link.bind("<Button-1>", lambda _event: open_license(self.root))
        legal_link.bind("<Return>", lambda _event: open_license(self.root))
        legal_link.bind("<space>", lambda _event: open_license(self.root))

    def _make_button(
        self,
        parent: tk.Misc,
        text: str,
        command: Callable[[], None],
        primary: bool = False,
        long_task: bool = False,
    ) -> ttk.Button:
        """统一创建按钮：主/次样式、正常悬停按下禁用状态由样式表提供。"""
        button = ttk.Button(
            parent,
            text=text,
            command=command,
            style="Primary.TButton" if primary else "Secondary.TButton",
        )
        if long_task:
            self._task_buttons.append(button)
        return button

    def _build_capture_tab(self, parent: ttk.Frame) -> None:
        theme = self.theme
        sp = theme.space
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(3, weight=1)

        browse_card = card(parent, theme)
        browse_card.grid(row=0, column=0, sticky="ew")
        browse_inner = browse_card.inner
        browse_inner.columnconfigure(0, weight=1, uniform="browse-status")
        browse_inner.columnconfigure(1, weight=1, uniform="browse-status")
        ttk.Label(
            browse_inner, text="页面阅览状态", style="Section.TLabel"
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, sp["sm"]))
        self.browse_badges: dict[str, StatusBadge] = {}
        browse_items = (
            ("pool", "卡池页面", 1, 0),
            ("history", "抽卡记录", 1, 1),
            ("wardrobe", "衣柜全部服装", 2, 0),
            ("background", "背景页面", 2, 1),
        )
        for key, label, row_index, column_index in browse_items:
            item = ttk.Frame(browse_inner, style="CardInner.TFrame")
            item.grid(
                row=row_index,
                column=column_index,
                sticky="ew",
                padx=(0, sp["lg"]) if column_index == 0 else (sp["lg"], 0),
                pady=sp["xs"],
            )
            ttk.Label(item, text=label, style="Soft.TLabel").pack(side="left")
            badge = StatusBadge(item, theme, "idle", "待检测")
            badge.pack(side="left", padx=(sp["sm"], 0))
            self.browse_badges[key] = badge

        # 状态卡片
        status_card = card(parent, theme)
        status_card.grid(row=1, column=0, sticky="ew", pady=(sp["md"], 0))
        inner = status_card.inner
        inner.columnconfigure(1, weight=1)
        ttk.Label(inner, text="采集状态", style="Section.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, sp["sm"])
        )
        self.capture_badge = StatusBadge(inner, theme, "idle", "未开始")
        self.capture_badge.grid(row=0, column=1, sticky="w",
                                padx=(sp["lg"], 0), pady=(0, sp["sm"]))
        ttk.Label(inner, text="当前会话", style="Soft.TLabel").grid(
            row=1, column=0, sticky="nw", pady=sp["xs"]
        )
        session_label = ttk.Label(inner, textvariable=self.session_var,
                                  style="Body.TLabel", justify="left")
        session_label.grid(row=1, column=1, sticky="w",
                           padx=(sp["lg"], 0), pady=sp["xs"])
        autowrap(session_label, margin=140)
        ttk.Label(inner, text="游戏流量", style="Soft.TLabel").grid(
            row=2, column=0, sticky="nw", pady=sp["xs"]
        )
        self.capture_traffic_badge = StatusBadge(
            inner, theme, "empty", "尚未开始"
        )
        self.capture_traffic_badge.grid(
            row=2, column=1, sticky="w", padx=(sp["lg"], 0), pady=sp["xs"]
        )
        ttk.Label(inner, text="环境检查", style="Soft.TLabel").grid(
            row=3, column=0, sticky="nw", pady=sp["xs"]
        )
        self.environment_badge = StatusBadge(inner, theme, "empty", "尚未检查")
        self.environment_badge.grid(row=3, column=1, sticky="w",
                                    padx=(sp["lg"], 0), pady=sp["xs"])
        env_label = ttk.Label(inner, textvariable=self.environment_var,
                              style="Soft.TLabel", justify="left")
        env_label.grid(row=4, column=1, sticky="w", padx=(sp["lg"], 0))
        autowrap(env_label, margin=140)

        # 操作区：主次分明
        actions_card = card(parent, theme)
        actions_card.grid(row=2, column=0, sticky="ew", pady=(sp["md"], 0))
        buttons = actions_card.inner
        self._make_button(
            buttons, "开始采集", self.start_capture, primary=True, long_task=True
        ).pack(side="left", padx=(0, sp["sm"]))
        self._make_button(
            buttons, "停止并生成报告", self.stop_capture, long_task=True
        ).pack(side="left", padx=sp["sm"])
        self._make_button(
            buttons, "环境检查", self.run_preflight, long_task=True
        ).pack(side="left", padx=sp["sm"])

        # 日志卡片
        log_card = card(parent, theme)
        log_card.grid(row=3, column=0, sticky="nsew", pady=(sp["md"], 0))
        log_inner = log_card.inner
        log_inner.columnconfigure(0, weight=1)
        log_inner.rowconfigure(1, weight=1)
        ttk.Label(log_inner, text="运行日志", style="Section.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, sp["sm"])
        )
        self.capture_log = ScrolledText(
            log_inner, height=12, wrap="word", state="disabled",
        )
        style_text_widget(self.capture_log, theme, mono=True)
        self.capture_log.grid(row=1, column=0, sticky="nsew")

    def _build_report_tab(self, parent: ttk.Frame) -> None:
        theme = self.theme
        sp = theme.space
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        # 摘要卡片
        summary_card = card(parent, theme)
        summary_card.grid(row=0, column=0, sticky="ew", pady=(sp["md"], 0))
        summary_inner = summary_card.inner
        summary_inner.columnconfigure(0, weight=1)
        self.report_badge = StatusBadge(
            summary_inner, theme, "empty", "尚未生成报告文件"
        )
        self.report_badge.grid(row=0, column=0, sticky="w", pady=(0, sp["xs"]))
        summary_label = ttk.Label(
            summary_inner, textvariable=self.report_summary_var,
            style="Body.TLabel", justify="left",
        )
        summary_label.grid(row=1, column=0, sticky="w")
        autowrap(summary_label)

        # 报告明细卡片
        detail_card = card(parent, theme)
        detail_card.grid(row=1, column=0, sticky="nsew", pady=(sp["md"], 0))
        detail_inner = detail_card.inner
        detail_inner.columnconfigure(0, weight=1)
        detail_inner.rowconfigure(1, weight=1)
        ttk.Label(detail_inner, text="证据明细", style="Section.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, sp["sm"])
        )
        self.report_text = ScrolledText(
            detail_inner, height=14, wrap="word", state="disabled",
        )
        style_text_widget(self.report_text, theme, mono=True)
        self.report_text.grid(row=1, column=0, sticky="nsew")

    def _build_import_tab(self, parent: ttk.Frame) -> None:
        theme = self.theme
        sp = theme.space
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        canvas = tk.Canvas(
            parent,
            background=theme.colors["app_bg"],
            highlightthickness=0,
            borderwidth=0,
        )
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        content = ttk.Frame(canvas, style="TFrame", padding=(0, 0, sp["xs"], sp["md"]))
        content.columnconfigure(0, weight=1)
        window = canvas.create_window((0, 0), window=content, anchor="nw")
        content.bind(
            "<Configure>",
            lambda _event: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.bind(
            "<Configure>",
            lambda event: canvas.itemconfigure(window, width=event.width),
        )
        self._import_scroll_canvas = canvas
        self._import_scroll_content = content
        self.root.bind_all("<MouseWheel>", self._on_import_mousewheel, add="+")

        # 设置与操作卡片
        settings_card = card(content, theme)
        settings_card.grid(row=0, column=0, sticky="ew")
        inner = settings_card.inner
        row = ttk.Frame(inner, style="CardInner.TFrame")
        row.pack(fill="x")
        ttk.Label(row, text="详情图显示宽度", style="Body.TLabel").pack(
            side="left", padx=(0, sp["sm"])
        )
        ttk.Spinbox(
            row, from_=120, to=1200, increment=1, width=8,
            textvariable=self.target_image_width_var,
        ).pack(side="left")
        ttk.Label(row, text="px", style="Soft.TLabel").pack(
            side="left", padx=(sp["xs"], 0)
        )
        protocol_link = tk.Label(
            row,
            text="查看压缩协议",
            background=theme.colors["card_bg"],
            foreground=theme.colors["pink_press"],
            activeforeground=theme.colors["pink_hover"],
            font=(*theme.fonts["body"], "underline"),
            cursor="hand2",
            takefocus=True,
            bd=0,
            padx=0,
            pady=0,
        )
        protocol_link.pack(side="right")
        protocol_link.bind("<Button-1>", lambda _event: self.show_protocol_spec())
        protocol_link.bind("<Return>", lambda _event: self.show_protocol_spec())
        protocol_link.bind("<space>", lambda _event: self.show_protocol_spec())
        actions = ttk.Frame(inner, style="CardInner.TFrame")
        actions.pack(fill="x", pady=(sp["md"], 0))
        self._make_button(
            actions, "生成完整导入码", self.generate_wechat_code, primary=True
        ).pack(side="left", padx=(0, sp["sm"]))

        # 覆盖警告条
        warning = Banner(
            content, theme, "warn",
            "本工具不执行导入。手动把原始 JSON 导入小程序时会覆盖当前账号；"
            "可匹配的普通池抽数会写入，未观测或无映射池保留 0，备注为空。"
            "DIY 定制服装没有小程序卡池槽位；紧凑文本与二维码仅在本机生成。",
        )
        warning.grid(row=1, column=0, sticky="ew", pady=(sp["md"], 0))

        # 生成结果摘要卡片
        summary_card = card(content, theme)
        summary_card.grid(row=2, column=0, sticky="ew", pady=(sp["md"], 0))
        summary_inner = summary_card.inner
        summary_inner.columnconfigure(0, weight=1)
        self.import_badge = StatusBadge(summary_inner, theme, "empty", "尚未生成")
        self.import_badge.grid(row=0, column=0, sticky="w", pady=(0, sp["xs"]))
        self.import_summary_frame = ttk.Frame(
            summary_inner, style="CardInner.TFrame"
        )
        self.import_summary_frame.grid(row=1, column=0, sticky="ew")
        self._set_import_summary(self.import_summary_text)

        self.import_text = self._build_artifact_text_card(
            content,
            row=3,
            column=0,
            title="原始 JSON",
            artifact="raw",
            height=8,
        )

        output_grid = ttk.Frame(content, style="TFrame")
        output_grid.grid(row=4, column=0, sticky="ew", pady=(sp["md"], 0))
        output_grid.columnconfigure(0, weight=1, uniform="compact-output")
        output_grid.columnconfigure(1, weight=1, uniform="compact-output")

        self.compressed_json_text = self._build_artifact_text_card(
            output_grid,
            row=0,
            column=0,
            title="压缩原始 JSON",
            artifact="compressed",
            height=18,
            padx=(0, sp["sm"]),
        )

        qr_card = card(output_grid, theme)
        qr_card.grid(row=0, column=1, sticky="nsew", padx=(sp["sm"], 0))
        qr_inner = qr_card.inner
        qr_inner.columnconfigure(0, weight=1)
        header = ttk.Frame(qr_inner, style="CardInner.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, sp["sm"]))
        header.columnconfigure(1, weight=1)
        ttk.Label(header, text="二维码", style="Section.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, sp["sm"])
        )
        selector = ttk.Combobox(
            header,
            textvariable=self.qr_kind_var,
            values=QR_KINDS,
            state="readonly",
            width=18,
        )
        selector.grid(row=0, column=1, sticky="e")
        selector.bind("<<ComboboxSelected>>", self._render_selected_qr)

        self.qr_canvas = tk.Canvas(
            qr_inner,
            width=320,
            height=320,
            background="#FFFFFF",
            highlightthickness=1,
            highlightbackground=theme.colors["input_border"],
            borderwidth=0,
        )
        self.qr_canvas.grid(row=1, column=0, pady=(0, sp["sm"]))
        qr_meta = ttk.Label(
            qr_inner,
            textvariable=self.qr_meta_var,
            style="Soft.TLabel",
            justify="left",
        )
        qr_meta.grid(row=2, column=0, sticky="ew", pady=(0, sp["sm"]))
        autowrap(qr_meta, margin=20)
        qr_actions = ttk.Frame(qr_inner, style="CardInner.TFrame")
        qr_actions.grid(row=3, column=0, sticky="w")
        self._make_button(
            qr_actions,
            "复制数据",
            lambda: self.copy_artifact("qr"),
        ).pack(side="left", padx=(0, sp["xs"]))
        self._make_button(
            qr_actions,
            "保存 PNG",
            self.save_qr_png,
        ).pack(side="left", padx=sp["xs"])
        self._make_button(
            qr_actions,
            "全屏",
            self.show_qr_fullscreen,
        ).pack(side="left", padx=sp["xs"])

        self.c1_base64_text = self._build_artifact_text_card(
            output_grid,
            row=1,
            column=0,
            title="C1 Base64 压缩",
            artifact="base64",
            height=10,
            pady=(sp["md"], 0),
            padx=(0, sp["sm"]),
        )
        self.c1_base4096_text = self._build_artifact_text_card(
            output_grid,
            row=1,
            column=1,
            title="C1 Base4096 压缩",
            artifact="base4096",
            height=10,
            pady=(sp["md"], 0),
            padx=(sp["sm"], 0),
        )

    def _build_artifact_text_card(
        self,
        parent: tk.Misc,
        *,
        row: int,
        column: int,
        title: str,
        artifact: str,
        height: int,
        padx: tuple[int, int] = (0, 0),
        pady: tuple[int, int] | None = None,
    ) -> ScrolledText:
        if pady is None:
            pady = (self.theme.space["md"], 0)
        panel = card(parent, self.theme)
        panel.grid(
            row=row,
            column=column,
            sticky="nsew",
            padx=padx,
            pady=pady,
        )
        inner = panel.inner
        inner.columnconfigure(0, weight=1)
        header = ttk.Frame(inner, style="CardInner.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, self.theme.space["sm"]))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text=title, style="Section.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        buttons = ttk.Frame(header, style="CardInner.TFrame")
        buttons.grid(row=0, column=1, sticky="e")
        self._make_button(
            buttons,
            "复制",
            lambda value=artifact: self.copy_artifact(value),
        ).pack(side="left", padx=(0, self.theme.space["xs"]))
        self._make_button(
            buttons,
            "另存",
            lambda value=artifact: self.save_artifact(value),
        ).pack(side="left")
        widget = ScrolledText(inner, height=height, wrap="char", state="disabled")
        style_text_widget(widget, self.theme, mono=True)
        widget.grid(row=1, column=0, sticky="nsew")
        return widget

    def _on_import_mousewheel(self, event: tk.Event) -> str | None:
        widget = event.widget
        if not self._is_descendant(widget, self._import_scroll_content):
            return None
        if isinstance(widget, (tk.Text, ttk.Combobox, ttk.Spinbox)):
            return None
        delta = int(-event.delta / 120) if event.delta else 0
        if delta:
            self._import_scroll_canvas.yview_scroll(delta, "units")
            return "break"
        return None

    @staticmethod
    def _is_descendant(widget: tk.Misc, ancestor: tk.Misc) -> bool:
        current: tk.Misc | None = widget
        while current is not None:
            if current == ancestor:
                return True
            current = current.master
        return False

    def _set_import_summary(self, text: str) -> None:
        """每行使用独立标签，避免宋体的多行度量造成文字重叠。"""
        self.import_summary_text = text
        for child in self.import_summary_frame.winfo_children():
            child.destroy()
        lines = text.splitlines() or [""]
        for index, line in enumerate(lines):
            label = tk.Label(
                self.import_summary_frame,
                text=line,
                background=self.theme.colors["card_bg"],
                foreground=self.theme.colors["text"],
                font=self.theme.fonts["body"],
                justify="left",
                anchor="w",
                bd=0,
                padx=0,
                pady=0,
            )
            label.pack(
                fill="x",
                anchor="w",
                pady=(0, 1 if index < len(lines) - 1 else 0),
            )
            autowrap(label)

    # ------------------------------------------------------------ 后台与忙碌
    def _set_busy(self, busy: bool, label: str) -> None:
        """长任务期间禁止重复点击，并显示忙碌进度条。"""
        self.busy_var.set(label)
        if busy:
            for button in self._task_buttons:
                button.state(["disabled"])
            if not self._busy_bar.winfo_ismapped():
                self._busy_bar.pack(side="left", padx=(10, 0))
                self._busy_bar.start(12)
        else:
            for button in self._task_buttons:
                button.state(["!disabled"])
            if self._busy_bar.winfo_ismapped():
                self._busy_bar.stop()
                self._busy_bar.pack_forget()

    def _submit(
        self,
        label: str,
        work: Callable[[], Any],
        on_success: Callable[[Any], None] | None = None,
    ) -> None:
        self._busy_count += 1
        self._set_busy(True, label)
        self._append_log(f"{label}...")

        def runner() -> None:
            try:
                result = work()
            except Exception as error:
                self._events.put(("error", label, error, None))
            else:
                self._events.put(("ok", label, result, on_success))

        threading.Thread(target=runner, name=f"yka-{label}", daemon=True).start()

    def _drain_events(self) -> None:
        while True:
            try:
                kind, label, value, callback = self._events.get_nowait()
            except queue.Empty:
                break
            if kind in {"live", "live_error", "live_retry"}:
                self._handle_live_analysis_event(kind, value)
                continue
            self._busy_count = max(0, self._busy_count - 1)
            if kind == "error":
                self._append_log(f"{label}失败：{value}")
                messagebox.showerror(APP_NAME, f"{label}失败\n\n{value}")
            else:
                self._append_log(f"{label}完成")
                if callback is not None:
                    try:
                        callback(value)
                    except Exception as error:
                        self._append_log(f"处理结果失败：{error}")
                        messagebox.showerror(APP_NAME, f"处理结果失败\n\n{error}")
            if self._busy_count == 0:
                self._set_busy(False, "就绪")
            else:
                self._set_busy(True, "任务进行中")
        self.root.after(100, self._drain_events)

    def _handle_live_analysis_event(self, kind: str, value: Any) -> None:
        if not isinstance(value, dict):
            return
        generation = value.get("generation")
        if generation != self._live_analysis_generation:
            return
        self._live_analysis_inflight = False
        if kind == "live_retry":
            self._live_analysis_last_revision = None
            self._live_analysis_retry_count += 1
            report = value.get("report")
            if self._live_analysis_retry_count >= 3 and isinstance(report, dict):
                warning = self._decode_warning_for_report(report)
                if warning:
                    self._set_live_decode_warning(warning)
            return
        if kind == "live_error":
            self._live_analysis_last_revision = None
            message = str(value.get("error") or "实时解析失败")
            if message != self._live_analysis_last_error:
                self._live_analysis_last_error = message
                self._append_log(f"实时页面检测暂时失败：{message}")
            return
        self._live_analysis_last_error = ""
        if self._last_state not in LIVE_CAPTURE_STATES:
            return
        session = value.get("session_dir")
        if not isinstance(session, str) or session != self._last_capture_session:
            return
        report = value.get("report")
        if not isinstance(report, dict):
            return
        self._live_analysis_retry_count = 0
        warning = self._decode_warning_for_report(report)
        self._set_live_decode_warning(warning)
        if warning:
            return
        snapshot = self._browse_status_snapshot(report)
        self._apply_browse_snapshot(snapshot, monotonic=True)

    def _set_live_decode_warning(self, warning: str) -> None:
        previous_warning = getattr(self, "_live_decode_warning", "")
        self._live_decode_warning = warning
        if warning:
            self.capture_traffic_badge.set("warn", warning)
            for badge in self.browse_badges.values():
                badge.set("warn", "等待可解码连接")
            if warning != previous_warning:
                self._append_log(
                    "检测到 9227 游戏流量，但服务端流无法解码。"
                    "请保持采集运行并重启游戏，再浏览相关页面。"
                )
        elif previous_warning:
            self.capture_traffic_badge.set("ok", "已抓到 · 游戏数据可解码")

    def _append_log(self, message: str) -> None:
        self.capture_log.configure(state="normal")
        self.capture_log.insert("end", message.rstrip() + "\n")
        self.capture_log.see("end")
        self.capture_log.configure(state="disabled")

    def _replace_text(self, widget: ScrolledText, value: str, readonly: bool) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        if readonly:
            widget.configure(state="disabled")

    # ---------------------------------------------------------------- 采集
    def run_preflight(self) -> None:
        self._submit("环境检查", preflight, self._show_preflight)

    def _show_preflight(self, result: dict[str, Any]) -> None:
        ready = bool(result.get("ready"))
        interfaces = result.get("selected_interface_names", [])
        game_files = result.get("game_executables", [])
        backend = str(result.get("capture_backend") or "未找到")
        if backend == "scapy":
            backend = "Scapy/Npcap"
        elif backend == "dumpcap":
            backend = "dumpcap（显式诊断模式）"
        components = result.get("required_components", {})
        if not isinstance(components, dict):
            components = {}
        npcap = components.get("npcap", {})
        scapy = components.get("scapy", {})
        npcap_installed = isinstance(npcap, dict) and bool(npcap.get("installed"))
        npcap_ready = isinstance(npcap, dict) and bool(npcap.get("ready"))
        scapy_installed = isinstance(scapy, dict) and bool(scapy.get("installed"))
        scapy_ready = isinstance(scapy, dict) and bool(scapy.get("ready"))
        self.environment_badge.set(
            "ok" if ready else "warn", "可采集" if ready else "未就绪"
        )
        self.environment_var.set(
            f"后端 {backend}；网卡 {', '.join(interfaces) if interfaces else '-'}；"
            f"Npcap {'就绪' if npcap_ready else ('已安装但不可用' if npcap_installed else '缺失')}；"
            f"Scapy {'就绪' if scapy_ready else ('已安装' if scapy_installed else '缺失')}；"
            f"游戏进程 {len(game_files)}"
        )
        self._append_log(json.dumps(result, ensure_ascii=False, indent=2))
        missing = [
            name
            for name, present in (("Npcap", npcap_installed), ("Scapy", scapy_installed))
            if not present
        ]
        if missing and not self._environment_repair_prompted:
            self._environment_repair_prompted = True
            if messagebox.askyesno(
                APP_NAME,
                "缺少必要组件："
                + "、".join(missing)
                + "。是否现在自动下载并安装？\n\n"
                "Npcap 将显示官方安装界面和 Windows 权限确认。",
            ):
                self._submit(
                    "安装必要组件",
                    lambda snapshot=result: self._install_required_components(snapshot),
                    self._show_preflight,
                )

    @staticmethod
    def _install_required_components(result: dict[str, Any]) -> dict[str, Any]:
        components = result.get("required_components", {})
        if not isinstance(components, dict):
            components = {}
        scapy = components.get("scapy", {})
        npcap = components.get("npcap", {})
        if not isinstance(scapy, dict) or not scapy.get("installed"):
            install_scapy()
        if not isinstance(npcap, dict) or not npcap.get("installed"):
            guide_install_npcap()
        return preflight()

    def start_capture(self) -> None:
        self._submit("启动采集", start_background, self._show_started)

    def _show_started(self, result: dict[str, Any]) -> None:
        self._reset_report_state()
        self._apply_status(result)
        session_value = result.get("session_dir")
        if isinstance(session_value, str) and session_value:
            try:
                live_report = build_live_coverage(Path(session_value))
                persistence = live_report.get("persistence", {})
                if isinstance(persistence, dict) and persistence.get("path"):
                    self._append_log(f"实时报告：{persistence['path']}")
            except Exception as error:
                self._append_log(f"初始化实时报告失败：{error}")
        self._append_log("采集器已启动。现在正常进入游戏并浏览需要记录的页面即可。")
        self._append_log(
            "游戏流量提示当前为“尚未抓到”；检测到 TCP/UDP 9227 数据后会自动变为绿色“已抓到”。"
        )

    def stop_capture(self) -> None:
        self._submit(
            "停止采集并生成报告文件",
            self._stop_and_build_report,
            self._show_stopped,
        )

    def _stop_and_build_report(self) -> dict[str, Any]:
        status = request_stop(timeout=30.0)
        state = str(status.get("state") or "")
        if state != "stopped":
            error = status.get("error") or f"采集器未正常停止：{state or '未知状态'}"
            raise RuntimeError(str(error))
        session_value = status.get("session_dir")
        if not isinstance(session_value, str) or not session_value:
            raise RuntimeError("采集器没有返回会话目录")
        report = build_session_report(Path(session_value))
        persistence = report.get("persistence", {})
        report_path = (
            persistence.get("path") if isinstance(persistence, dict) else None
        )
        final_status = {
            **status,
            "state": "stopped",
            "analysis_pending": False,
            "report_path": report_path,
            "report_persisted": bool(report_path),
        }
        return {"status": final_status, "report": report}

    def _show_stopped(self, result: dict[str, Any]) -> None:
        status = result.get("status", {})
        if not isinstance(status, dict):
            status = {"state": "stopped"}
        self._apply_status(status)
        report = result.get("report")
        if not isinstance(report, dict):
            raise ValueError("报告根节点不是对象")
        self._current_report = report
        self._report_revision += 1
        self._clear_import_output()
        self._show_report(report)

    def _poll_collector_status(self) -> None:
        status = current_capture_status()
        if isinstance(status, dict):
            state = str(status.get("state") or "not_started")
            previous_state = self._last_state
            session = status.get("session_dir")
            belongs_to_current_run = bool(
                self._last_capture_session
                and isinstance(session, str)
                and session == self._last_capture_session
            )
            active_states = {
                "starting_capture",
                "waiting_for_game",
                "capturing",
                "draining_capture",
                "analyzing",
                "stop_pending",
            }
            collector_disappeared = bool(
                previous_state in {
                    "starting_capture",
                    "waiting_for_game",
                    "capturing",
                    "draining_capture",
                    "analyzing",
                    "stop_pending",
                }
                and state in {"not_started", "not_running", "failed"}
            )
            if state in active_states or belongs_to_current_run or collector_disappeared:
                self._apply_status(status, log_change=True)
                if previous_state in LIVE_CAPTURE_STATES and state not in LIVE_CAPTURE_STATES:
                    self._invalidate_live_analysis()
                else:
                    self._maybe_start_live_analysis(status)
        self.root.after(1000, self._poll_collector_status)

    def _invalidate_live_analysis(self) -> None:
        self._live_analysis_generation += 1
        self._live_analysis_inflight = False
        self._live_analysis_last_revision = None
        self._live_analysis_retry_count = 0

    @staticmethod
    def _capture_revision(session_dir: Path) -> tuple[tuple[str, int, int], ...]:
        revision: list[tuple[str, int, int]] = []
        try:
            paths = sorted((session_dir / "pcap").glob("*.pcapng"))
        except OSError:
            return ()
        for path in paths:
            try:
                stat = path.stat()
            except OSError:
                return ()
            if stat.st_size > 0:
                revision.append((path.name, stat.st_size, stat.st_mtime_ns))
        return tuple(revision)

    def _maybe_start_live_analysis(self, status: dict[str, Any]) -> None:
        state = str(status.get("state") or "")
        if state not in LIVE_CAPTURE_STATES or self._live_analysis_inflight:
            return
        if status.get("capture_has_packets") is not True:
            raw_packets = status.get("capture_packets")
            if not (type(raw_packets) is int and raw_packets > 0):
                return
        session_value = status.get("session_dir")
        if not isinstance(session_value, str) or not session_value:
            return
        session_dir = Path(session_value).resolve()
        revision = self._capture_revision(session_dir)
        if not revision or revision == self._live_analysis_last_revision:
            return
        now = time.monotonic()
        if now - self._live_analysis_last_started < LIVE_ANALYSIS_INTERVAL_SECONDS:
            return

        generation = self._live_analysis_generation
        self._live_analysis_inflight = True
        self._live_analysis_last_started = now
        self._live_analysis_last_revision = revision

        def runner() -> None:
            try:
                report = build_live_coverage(session_dir)
            except Exception as error:
                self._events.put(
                    (
                        "live_error",
                        "实时页面检测",
                        {
                            "generation": generation,
                            "session_dir": str(session_dir),
                            "error": f"{type(error).__name__}: {error}",
                        },
                        None,
                    )
                )
            else:
                protocol_decode = report.get("protocol_decode", {})
                decode_status = (
                    str(protocol_decode.get("status") or "")
                    if isinstance(protocol_decode, dict)
                    else ""
                )
                kind = "live_retry" if decode_status == "decode_error" else "live"
                self._events.put(
                    (
                        kind,
                        "实时页面检测",
                        {
                            "generation": generation,
                            "session_dir": str(session_dir),
                            "report": report,
                        },
                        None,
                    )
                )

        threading.Thread(
            target=runner,
            name="yka-live-page-analysis",
            daemon=True,
        ).start()

    def _apply_status(self, status: dict[str, Any], log_change: bool = False) -> None:
        state = str(status.get("state") or "not_started")
        label = STATE_LABELS.get(state, state)
        self.capture_state_var.set(label)
        self.capture_badge.set(STATE_SEMANTICS.get(state, "idle"), label)
        session = status.get("session_dir")
        if isinstance(session, str) and session:
            if session != self._last_capture_session:
                self._last_capture_session = session
                self._last_capture_hit = False
            self._active_session = Path(session)
            self.session_var.set(session)
        traffic_semantic, traffic_label, has_packets = capture_traffic_feedback(status)
        if has_packets and self._live_decode_warning:
            traffic_semantic = "warn"
            traffic_label = self._live_decode_warning
        self.capture_traffic_badge.set(traffic_semantic, traffic_label)
        if log_change and has_packets and not self._last_capture_hit:
            self._append_log(f"抓包命中：{traffic_label}")
        self._last_capture_hit = self._last_capture_hit or has_packets
        if log_change and state != self._last_state:
            self._append_log(f"状态：{label}")
        self._last_state = state

    # ---------------------------------------------------------------- 报告
    @staticmethod
    def _gacha_history_count(history: dict[str, Any]) -> int:
        entries = history.get("entries", [])
        if not isinstance(entries, list):
            return 0
        total = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            count = entry.get("count")
            if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                total += count
        return total

    @staticmethod
    def _nonnegative_int(value: Any) -> int:
        return value if type(value) is int and value >= 0 else 0

    @staticmethod
    def _decode_warning_for_report(report: dict[str, Any]) -> str:
        protocol = report.get("protocol_decode", {})
        if not isinstance(protocol, dict):
            return ""
        status = str(protocol.get("status") or "")
        streams = protocol.get("streams", [])
        if not isinstance(streams, list):
            streams = []
        unresolved = any(
            isinstance(stream, dict)
            and stream.get("transport_mode") == "unresolved"
            and ReporterApp._nonnegative_int(stream.get("tcp_payload_bytes")) > 0
            for stream in streams
        )
        decoded = any(
            isinstance(stream, dict)
            and stream.get("transport_mode") not in {None, "unresolved"}
            and ReporterApp._nonnegative_int(stream.get("complete_frames")) > 0
            for stream in streams
        )
        if status == "decode_error" or (unresolved and not decoded):
            return "无法解码 · 请重启游戏连接"
        return ""

    @classmethod
    def _browse_status_snapshot(cls, report: dict[str, Any]) -> dict[str, Any]:
        coverage = report.get("data_coverage", {})
        if not isinstance(coverage, dict):
            coverage = {}
        wardrobe = coverage.get("wardrobe_presence", {})
        pool = coverage.get("pool_presence", {})
        draw = coverage.get("draw_count", {})
        history = coverage.get("gacha_history", {})
        photo = coverage.get("photo_info", {})
        if not isinstance(wardrobe, dict):
            wardrobe = {}
        if not isinstance(pool, dict):
            pool = {}
        if not isinstance(draw, dict):
            draw = {}
        if not isinstance(history, dict):
            history = {}
        if not isinstance(photo, dict):
            photo = {}

        wardrobe_count = cls._nonnegative_int(wardrobe.get("fashion_count"))
        standard_count = cls._nonnegative_int(
            wardrobe.get("standard_fashion_count")
        )
        diy_count = cls._nonnegative_int(wardrobe.get("diy_fashion_count"))
        pools = pool.get("pools", [])
        pool_count = len(pools) if isinstance(pools, list) else 0
        history_count = cls._gacha_history_count(history)
        draw_pool_count = cls._nonnegative_int(draw.get("observed_pool_count"))
        complete = bool(wardrobe.get("full_wardrobe_complete"))
        pool_complete = bool(pool.get("completeness"))
        draw_status = str(draw.get("status") or "unobserved")
        draw_observed = draw_pool_count > 0 or draw_status in {
            "observed_present",
            "observed_absent",
        }
        draw_complete = bool(
            draw_observed
            and draw.get("snapshot_complete")
            and draw.get("completeness")
        )
        photo_count = cls._nonnegative_int(photo.get("count"))
        photo_catalog = photo.get("background_catalog", {})
        if not isinstance(photo_catalog, dict):
            photo_catalog = {}
        background_count = cls._nonnegative_int(
            photo_catalog.get("matched_records")
        )
        photo_complete = bool(photo.get("completeness"))

        if draw_complete:
            history_badge = {
                "semantic": "ok",
                "label": f"已浏览 · {draw_pool_count} 池抽数",
                "progress": (draw_pool_count, history_count),
            }
        elif draw_observed or draw_status == "partial":
            history_badge = {
                "semantic": "warn",
                "label": f"部分 · {draw_pool_count} 池抽数",
                "progress": (draw_pool_count, history_count),
            }
        elif history_count:
            history_badge = {
                "semantic": "warn",
                "label": f"仅本次抽取 · {history_count} 次",
                "progress": (0, history_count),
            }
        else:
            history_badge = {
                "semantic": "empty",
                "label": "未观测 · 0 池抽数",
                "progress": (0, 0),
            }

        return {
            "wardrobe": wardrobe,
            "pool": pool,
            "draw": draw,
            "history": history,
            "photo": photo,
            "wardrobe_count": wardrobe_count,
            "standard_count": standard_count,
            "diy_count": diy_count,
            "pool_count": pool_count,
            "history_count": history_count,
            "draw_pool_count": draw_pool_count,
            "complete": complete,
            "pool_complete": pool_complete,
            "draw_complete": draw_complete,
            "photo_count": photo_count,
            "background_count": background_count,
            "photo_complete": photo_complete,
            "badges": {
                "pool": {
                    "semantic": (
                        "ok" if pool_complete else ("warn" if pool_count else "empty")
                    ),
                    "label": (
                        f"已浏览 · {pool_count} 池"
                        if pool_complete
                        else (
                            f"部分 · {pool_count} 池"
                            if pool_count
                            else "未观测 · 0 池"
                        )
                    ),
                    "progress": (pool_count,),
                },
                "history": history_badge,
                "wardrobe": {
                    "semantic": (
                        "ok" if complete else ("warn" if wardrobe_count else "empty")
                    ),
                    "label": (
                        f"已浏览 · {wardrobe_count} 件"
                        if complete
                        else (
                            f"部分 · {wardrobe_count} 件"
                            if wardrobe_count
                            else "未观测 · 0 件"
                        )
                    ),
                    "progress": (wardrobe_count,),
                },
                "background": {
                    "semantic": (
                        "ok" if photo_complete else ("warn" if photo_count else "empty")
                    ),
                    "label": (
                        f"已浏览 · {background_count}/{photo_count}"
                        if photo_complete
                        else (
                            f"部分 · {background_count}/{photo_count}"
                            if photo_count
                            else "未观测 · 0"
                        )
                    ),
                    "progress": (photo_count, background_count),
                },
            },
        }

    def _apply_browse_snapshot(
        self,
        snapshot: dict[str, Any],
        *,
        monotonic: bool,
    ) -> None:
        badges = snapshot.get("badges", {})
        if not isinstance(badges, dict):
            return
        if not monotonic:
            self._live_browse_badges = {}
        semantic_rank = {"empty": 0, "idle": 0, "warn": 1, "ok": 2}
        for key, widget in self.browse_badges.items():
            candidate = badges.get(key)
            if not isinstance(candidate, dict):
                continue
            selected = candidate
            previous = self._live_browse_badges.get(key)
            if monotonic and isinstance(previous, dict):
                previous_key = (
                    semantic_rank.get(str(previous.get("semantic")), 0),
                    tuple(previous.get("progress", ())),
                )
                candidate_key = (
                    semantic_rank.get(str(candidate.get("semantic")), 0),
                    tuple(candidate.get("progress", ())),
                )
                if previous_key > candidate_key:
                    selected = previous
            self._live_browse_badges[key] = dict(selected)
            widget.set(
                str(selected.get("semantic") or "empty"),
                str(selected.get("label") or "未观测"),
            )

    def _reset_report_state(self) -> None:
        self._invalidate_live_analysis()
        self._live_analysis_last_started = 0.0
        self._live_analysis_last_error = ""
        self._live_decode_warning = ""
        self._live_browse_badges = {}
        self._current_report = None
        self._report_revision += 1
        self._clear_import_output()
        self.report_badge.set("empty", "尚未生成报告文件")
        self.report_summary_var.set("尚未生成报告文件")
        self._replace_text(self.report_text, "", readonly=True)
        for badge in self.browse_badges.values():
            badge.set("idle", "待检测")

    def _show_report(self, report: dict[str, Any]) -> None:
        snapshot = self._browse_status_snapshot(report)
        self._apply_browse_snapshot(snapshot, monotonic=False)
        decode_warning = self._decode_warning_for_report(report)
        self._set_live_decode_warning(decode_warning)
        wardrobe = snapshot["wardrobe"]
        pool = snapshot["pool"]
        draw = snapshot["draw"]
        history = snapshot["history"]
        photo = snapshot["photo"]
        wardrobe_count = snapshot["wardrobe_count"]
        standard_count = snapshot["standard_count"]
        diy_count = snapshot["diy_count"]
        pool_count = snapshot["pool_count"]
        history_count = snapshot["history_count"]
        draw_pool_count = snapshot["draw_pool_count"]
        complete = snapshot["complete"]
        pool_complete = snapshot["pool_complete"]
        draw_complete = snapshot["draw_complete"]
        photo_count = snapshot["photo_count"]
        background_count = snapshot["background_count"]
        photo_complete = snapshot["photo_complete"]

        has_data = (
            wardrobe_count
            or pool_count
            or draw_pool_count
            or history_count
            or photo_count
        )
        if decode_warning:
            self.report_badge.set("warn", "已抓到 · 无法解码")
        elif not has_data:
            self.report_badge.set("empty", "未检测到数据")
        elif complete:
            self.report_badge.set("ok", "已载入 · 完整快照")
        else:
            self.report_badge.set("warn", "已载入 · 快照不完整")
        self.report_summary_var.set(
            ("服务端流无法解码，请保持采集运行并重启游戏。\n" if decode_warning else "")
            + f"衣柜 {wardrobe_count}（标准 {standard_count}，DIY {diy_count}），"
            f"完整快照：{'是' if complete else '否'}\n"
            f"卡池 {pool_count}；累计抽数快照 {draw_pool_count} 池；"
            f"本次抽取结果 {history_count} 次；"
            f"背景记录 {photo_count}（已映射 {background_count}）"
        )
        persistence = report.get("persistence", {})
        if not isinstance(persistence, dict):
            persistence = {}
        summary = {
            "报告": {
                "状态": persistence.get("state"),
                "文件": persistence.get("path"),
            },
            "生成时间": report.get("generated_at"),
            "协议解析": {
                "status": (
                    report.get("protocol_decode", {}).get("status")
                    if isinstance(report.get("protocol_decode"), dict)
                    else None
                ),
                "warning": decode_warning or None,
                "errors": report.get("capture_parse_errors", []),
            },
            "衣柜证据": {
                "status": wardrobe.get("status"),
                "full_wardrobe_complete": complete,
                "fashion_count": wardrobe_count,
                "standard_fashion_count": standard_count,
                "diy_fashion_count": diy_count,
            },
            "卡池证据": {
                "status": pool.get("status"),
                "completeness": pool_complete,
                "pool_count": pool_count,
            },
            "抽卡记录": {
                "status": draw.get("status"),
                "snapshot_complete": draw_complete,
                "observed_pool_count": draw_pool_count,
                "captured_result_status": history.get("status"),
                "captured_result_count": history_count,
            },
            "背景证据": {
                "status": photo.get("status"),
                "completeness": photo_complete,
                "record_count": photo_count,
                "matched_background_count": background_count,
            },
        }
        self._replace_text(
            self.report_text,
            json.dumps(summary, ensure_ascii=False, indent=2),
            readonly=True,
        )

    # ---------------------------------------------------------------- 导入码
    def _clear_import_output(self) -> None:
        self._last_import_result = None
        self._last_raw_import_code = None
        self._last_import_artifacts = None
        self._last_import_report_revision = None
        for widget in (
            self.import_text,
            self.compressed_json_text,
            self.c1_base64_text,
            self.c1_base4096_text,
        ):
            self._replace_text(widget, "", readonly=True)
        self._qr_source_image = None
        self._qr_preview_photo = None
        self._qr_metadata = None
        self.qr_canvas.delete("all")
        self.qr_meta_var.set("尚未生成")
        self.import_badge.set("empty", "尚未生成")
        self._set_import_summary("尚未生成")

    def _wechat_export_payload(
        self,
        raw_json: str,
        target_width: int,
        artifacts: ImportArtifacts | None = None,
    ) -> dict[str, Any]:
        if self._active_session is None or self._current_report is None:
            raise RuntimeError("当前会话或最终报告不可用")
        report_generated_at = self._current_report.get("generated_at")
        persistence = self._current_report.get("persistence", {})
        if not isinstance(report_generated_at, str) or not report_generated_at:
            raise RuntimeError("最终报告缺少生成时间")
        if not isinstance(persistence, dict) or persistence.get("state") != "final":
            raise RuntimeError("最终报告尚未落盘")
        transports = {"raw_json": raw_json}
        catalog_id: str | None = None
        codec_id: int | None = None
        if artifacts is not None:
            transports.update(
                {
                    "compressed_json": artifacts.compressed_json,
                    "c1_base64": artifacts.c1_base64,
                    "c1_base4096": artifacts.c1_base4096,
                }
            )
            catalog_id = artifacts.catalog_id
            codec_id = artifacts.codec_id
        return {
            "schema_version": 1,
            "generated_at": now_iso(),
            "app": APP_NAME,
            "version": APP_VERSION,
            "session_dir": str(self._active_session.resolve()),
            "report_generated_at": report_generated_at,
            "report_path": persistence.get("path"),
            "catalog_id": catalog_id,
            "codec_id": codec_id,
            "target_width": target_width,
            "transports": transports,
        }

    def _persist_raw_wechat_export(self, raw_json: str, target_width: int) -> Path:
        if self._active_session is None:
            raise RuntimeError("当前会话不可用")
        payload = self._wechat_export_payload(raw_json, target_width)
        return persist_wechat_export(self._active_session, payload)

    def _persist_wechat_export_and_cleanup(
        self,
        artifacts: ImportArtifacts,
    ) -> tuple[Path, dict[str, Any]]:
        if self._active_session is None:
            raise RuntimeError("当前会话不可用")
        payload = self._wechat_export_payload(
            artifacts.raw_json,
            artifacts.target_width,
            artifacts,
        )
        export_path = persist_wechat_export(self._active_session, payload)
        cleanup = cleanup_session_capture_files(self._active_session)
        return export_path, cleanup

    def generate_wechat_code(self) -> None:
        self._clear_import_output()
        try:
            if self._current_report is None:
                raise ImportDataError("尚未生成最终报告，请先完成一次采集")
            target_width = int(self.target_image_width_var.get().strip())
            result = generate_import_code_from_report(
                self._current_report,
                POOL_CATALOG_PATH,
                target_image_width_px=target_width,
            )
        except (ImportDataError, KeyError, OSError, TypeError, ValueError) as error:
            self.import_badge.set("error", "生成失败")
            messagebox.showerror(APP_NAME, f"生成失败\n\n{error}")
            return

        self._last_import_result = result
        self._last_raw_import_code = result.code
        self._last_import_report_revision = self._report_revision
        self._replace_text(self.import_text, result.code, readonly=True)

        raw_export_path: Path | None = None
        raw_export_error = ""
        try:
            raw_export_path = self._persist_raw_wechat_export(result.code, target_width)
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            raw_export_error = str(error)
            self._append_log(f"原始微信导入 JSON 落盘失败：{error}")

        try:
            artifacts = build_import_artifacts(
                result.code,
                catalog_path=COMPACT_CATALOG_PATH,
                registry_path=COMPACT_REGISTRY_PATH,
                target_width=target_width,
                expected_pool_keys=tuple(
                    record.pool_key for record in result.records
                ),
            )
        except (ArtifactError, KeyError, OSError, TypeError, ValueError) as error:
            cleanup_text = ""
            if raw_export_path is not None and self._active_session is not None:
                try:
                    cleanup = cleanup_session_capture_files(self._active_session)
                except (OSError, RuntimeError, TypeError, ValueError) as cleanup_error:
                    cleanup_text = f"；抓包清理失败：{cleanup_error}"
                    self._append_log(f"抓包清理失败：{cleanup_error}")
                else:
                    cleanup_text = (
                        f"；已清理抓包文件 "
                        f"{int(cleanup.get('removed_file_count') or 0)} 个"
                    )
            raw_storage = (
                f"原始导出文件 {raw_export_path}{cleanup_text}"
                if raw_export_path is not None
                else f"原始导出文件落盘失败：{raw_export_error or '未知错误'}"
            )
            warning_text = "\n".join(f"- {item}" for item in result.warnings)
            self.import_badge.set("warn", "原始 JSON 已生成")
            self._set_import_summary(
                f"原始微信导入 JSON 已生成，"
                f"共 {len(result.records)} 条、{len(result.code.encode('utf-8'))} B。\n"
                f"{raw_storage}\n"
                f"紧凑格式生成失败：{error}\n"
                f"{warning_text}"
            )
            messagebox.showwarning(
                APP_NAME,
                "原始微信导入 JSON 已生成，可直接复制或保存。\n\n"
                f"压缩格式与二维码生成失败：{error}",
            )
            return

        self._last_import_artifacts = artifacts
        self._replace_text(
            self.compressed_json_text,
            artifacts.compressed_json,
            readonly=True,
        )
        self._replace_text(
            self.c1_base64_text,
            artifacts.c1_base64,
            readonly=True,
        )
        self._replace_text(
            self.c1_base4096_text,
            artifacts.c1_base4096,
            readonly=True,
        )
        self._render_selected_qr()
        persistence_error = ""
        storage_text = ""
        try:
            export_path, cleanup = self._persist_wechat_export_and_cleanup(artifacts)
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            persistence_error = str(error)
            storage_text = f"导出数据或抓包清理失败：{error}"
            self._append_log(storage_text)
            messagebox.showwarning(
                APP_NAME,
                "导入码已经生成，但导出数据落盘或抓包清理失败。\n\n"
                f"{error}",
            )
        else:
            removed_count = int(cleanup.get("removed_file_count") or 0)
            storage_text = (
                f"导出文件 {export_path}；已清理抓包文件 {removed_count} 个"
            )
            self._append_log(storage_text)
        warning_text = "\n".join(f"- {item}" for item in result.warnings)
        status_counts: dict[int, int] = {}
        for record in result.records:
            if record.background:
                continue
            status_counts[record.status_code] = status_counts.get(record.status_code, 0) + 1
        status_text = "、".join(
            f"{IMPORT_STATUS_LABELS[status_code]} {count}"
            for status_code, count in sorted(status_counts.items())
        )
        unresolved = (
            result.unresolved_piece_pool_count + result.unresolved_status_pool_count
        )
        if (
            persistence_error
            or unresolved
            or result.unobserved_draw_count
            or result.draw_evidence_level in {"candidate", "mixed"}
        ):
            self.import_badge.set("warn", "已生成 · 含待人工确认项")
        else:
            self.import_badge.set("ok", "已生成")
        self._set_import_summary(
            f"输出 {len(result.records)}/{result.catalog_pool_count} 条；"
            f"逐件完整 {result.complete_piece_pool_count} 池；"
            f"已选卡池槽位服装 {result.marked_owned_piece_count}/{result.mapped_piece_count} 件；"
            f"主服装已拥有 {result.owned_main_count}；全齐 {result.full_set_count}；"
            f"旧图未解 {result.unresolved_piece_pool_count} 池；"
            f"状态未解 {result.unresolved_status_pool_count} 池\n"
            f"普通池抽数：已写入 {result.observed_draw_pool_count} 池，"
            f"未观测或无映射 {result.unobserved_draw_count} 池保留 0；"
            f"服务器响应 {result.observed_draw_source_pool_count} 池，"
            f"未映射 {result.unmapped_server_draw_pool_count} 池；"
            f"证据 {result.draw_evidence_level}；背景池 {result.background_pool_count} 条\n"
            f"状态分布：{status_text}\n"
            f"紧凑目录 {artifacts.catalog_id}；codec {artifacts.codec_id}；"
            f"原始 {len(artifacts.raw_json.encode('utf-8'))} B；"
            f"压缩原始 {len(artifacts.compressed_json)} 字符；"
            f"C1 wire {len(artifacts.wire)} B；"
            f"Base64 {len(artifacts.c1_base64)} 字符；"
            f"Base4096 {len(artifacts.c1_base4096)} 字符\n"
            f"{storage_text}\n"
            f"{warning_text}"
        )

    def _require_current_artifacts(self) -> ImportArtifacts:
        if (
            self._current_report is None
            or self._last_import_report_revision != self._report_revision
            or self._last_import_artifacts is None
        ):
            raise ValueError("当前输出不是由本次报告生成，请重新生成")
        return self._last_import_artifacts

    def _require_current_raw_import_code(self) -> str:
        if (
            self._current_report is None
            or self._last_import_report_revision != self._report_revision
            or self._last_raw_import_code is None
        ):
            raise ValueError("当前原始 JSON 不是由本次报告生成，请重新生成")
        return self._last_raw_import_code

    def _current_import_code(self) -> str:
        value = self._require_current_raw_import_code()
        catalog = load_pool_catalog(POOL_CATALOG_PATH)
        known_keys = {
            pool["key"]
            for pool in catalog.get("pools", [])
            if isinstance(pool, dict)
        }
        known_background = {
            pool["key"]
            for pool in catalog.get("pools", [])
            if isinstance(pool, dict)
            and str(
                pool.get(
                    "pool_type",
                    pool.get(
                        "type",
                        pool.get(
                            "kind",
                            pool.get("att_type", pool.get("attType", "")),
                        ),
                    ),
                )
            ).lower()
            in {"background", "bg", "attbg"}
        }
        validate_import_code(
            value,
            known_keys,
            known_background,
            require_all_known_keys=True,
        )
        return value

    def _artifact_value(self, artifact: str) -> tuple[str, str]:
        if artifact == "raw":
            return "原始 JSON", self._require_current_raw_import_code()
        artifacts = self._require_current_artifacts()
        values = {
            "compressed": ("压缩原始 JSON", artifacts.compressed_json),
            "base64": ("C1 Base64", artifacts.c1_base64),
            "base4096": ("C1 Base4096", artifacts.c1_base4096),
        }
        if artifact == "qr":
            kind = self.qr_kind_var.get()
            return kind, artifacts.qr_payload(kind)
        try:
            return values[artifact]
        except KeyError as error:
            raise ValueError("未知输出类型") from error

    def copy_artifact(self, artifact: str) -> None:
        try:
            label, value = self._artifact_value(artifact)
        except Exception as error:
            messagebox.showerror(APP_NAME, str(error))
            return
        if artifact == "raw":
            candidate_note = ""
            if (
                self._last_import_result is not None
                and self._last_import_result.observed_draw_pool_count
                and self._last_import_result.draw_evidence_level
                in {"candidate", "mixed"}
            ):
                candidate_note = (
                    "\n\n本报告的抽数包含候选协议证据，已经过单响应和目录一致性校验，"
                    "但不是直接消息证据。"
                )
            if not messagebox.askyesno(
                APP_NAME,
                "小程序导入会覆盖当前账号。确认已先导出现有记录，再复制原始 JSON？"
                + candidate_note,
            ):
                return
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.root.update_idletasks()
        self.busy_var.set(f"{label} 已复制")

    def save_artifact(self, artifact: str) -> None:
        try:
            label, value = self._artifact_value(artifact)
        except Exception as error:
            messagebox.showerror(APP_NAME, str(error))
            return
        is_json = artifact == "raw"
        names = {
            "raw": "wechat-import-code.json",
            "compressed": "wechat-import-compressed-j1.txt",
            "base64": "wechat-import-c1-base64.txt",
            "base4096": "wechat-import-c1-base4096.txt",
        }
        target = filedialog.asksaveasfilename(
            title=f"保存{label}",
            defaultextension=".json" if is_json else ".txt",
            initialfile=names.get(artifact, "wechat-import-code.txt"),
            filetypes=(
                [("JSON", "*.json"), ("Text", "*.txt")]
                if is_json
                else [("Text", "*.txt")]
            ),
        )
        if target:
            try:
                Path(target).write_text(value + "\n", encoding="utf-8")
            except OSError as error:
                messagebox.showerror(APP_NAME, f"保存失败\n\n{error}")
                return
            self.busy_var.set(f"{label} 已保存")

    def copy_import_code(self) -> None:
        self.copy_artifact("raw")

    def save_import_code(self) -> None:
        self.save_artifact("raw")

    @staticmethod
    def _as_pil_image(image: Any) -> Image.Image:
        value = image.get_image() if hasattr(image, "get_image") else image
        if not isinstance(value, Image.Image):
            raise ValueError("二维码渲染器没有返回 Pillow 图像")
        return value

    def _render_selected_qr(self, _event: tk.Event | None = None) -> None:
        self.qr_canvas.delete("all")
        self._qr_source_image = None
        self._qr_preview_photo = None
        self._qr_metadata = None
        if self._last_import_artifacts is None:
            self.qr_meta_var.set("尚未生成")
            return
        kind = self.qr_kind_var.get()
        try:
            payload = self._last_import_artifacts.qr_payload(kind)
            rendered, metadata = export_qr(kind, payload)
            source = self._as_pil_image(rendered).copy()
        except Exception as error:
            self.qr_meta_var.set(f"二维码生成失败：{qr_error_text(kind, error)}")
            self.qr_canvas.create_text(
                160,
                160,
                text="二维码生成失败",
                fill=self.theme.colors["rose_text"],
                font=self.theme.fonts["body"],
            )
            return

        preview = source.resize((304, 304), Image.Resampling.NEAREST)
        self._qr_source_image = source
        self._qr_preview_photo = ImageTk.PhotoImage(preview)
        self._qr_metadata = metadata
        self.qr_canvas.create_image(160, 160, image=self._qr_preview_photo)
        self.qr_meta_var.set(qr_metadata_text(kind, metadata))

    def save_qr_png(self) -> None:
        try:
            kind, _payload = self._artifact_value("qr")
            if self._qr_source_image is None:
                raise ValueError("尚未生成当前二维码")
        except Exception as error:
            messagebox.showerror(APP_NAME, str(error))
            return
        slug = {
            QR_KINDS[0]: "compressed-json",
            QR_KINDS[1]: "c1-base64",
            QR_KINDS[2]: "c1-base4096",
        }[kind]
        target = filedialog.asksaveasfilename(
            title=f"保存{kind}二维码",
            defaultextension=".png",
            initialfile=f"yka-{slug}-qr.png",
            filetypes=[("PNG", "*.png")],
        )
        if target:
            try:
                self._qr_source_image.save(target, format="PNG")
            except OSError as error:
                messagebox.showerror(APP_NAME, f"保存失败\n\n{error}")
                return
            self.busy_var.set(f"{kind}二维码已保存")

    def show_qr_fullscreen(self) -> None:
        try:
            kind, payload = self._artifact_value("qr")
            if self._qr_metadata is None:
                raise ValueError("尚未生成当前二维码")
            available = min(self.root.winfo_screenwidth(), self.root.winfo_screenheight()) - 24
            total_modules = self._qr_metadata.modules + 2 * self._qr_metadata.border
            box_size = max(1, min(8, available // total_modules))
            rendered, _metadata = export_qr(
                kind,
                payload,
                box_size=box_size,
                border=4,
            )
            image = self._as_pil_image(rendered)
        except Exception as error:
            messagebox.showerror(APP_NAME, str(error))
            return

        window = tk.Toplevel(self.root)
        window.configure(background="#FFFFFF")
        window.attributes("-fullscreen", True)
        photo = ImageTk.PhotoImage(image)
        label = tk.Label(window, image=photo, background="#FFFFFF", borderwidth=0)
        label.image = photo
        label.pack(expand=True)
        window.bind("<Escape>", lambda _event: window.destroy())
        window.bind("<Button-1>", lambda _event: window.destroy())
        window.focus_force()

    def show_protocol_spec(self) -> None:
        try:
            content = PROTOCOL_SPEC_PATH.read_text(encoding="utf-8")
        except OSError as error:
            messagebox.showerror(APP_NAME, f"无法读取压缩协议\n\n{error}")
            return
        window = tk.Toplevel(self.root)
        window.title("压缩协议阅览")
        window.geometry("900x680")
        window.minsize(640, 420)
        window.configure(background=self.theme.colors["app_bg"])
        viewer = ScrolledText(window, wrap="word", state="normal")
        render_markdown(viewer, content, self.theme)
        viewer.pack(
            fill="both",
            expand=True,
            padx=self.theme.space["lg"],
            pady=self.theme.space["lg"],
        )
        window.bind("<Escape>", lambda _event: window.destroy())
        window.transient(self.root)
        window.focus_set()

    # ---------------------------------------------------------------- 其他
    def open_active_session(self) -> None:
        if self._active_session is None:
            messagebox.showinfo(APP_NAME, "当前没有会话目录。")
            return
        self._open_directory(self._active_session)

    def _open_directory(self, path: Path) -> None:
        path = path.resolve()
        if not path.is_dir():
            messagebox.showerror(APP_NAME, f"目录不存在：{path}")
            return
        if os.name != "nt":
            messagebox.showerror(APP_NAME, "当前版本只支持 Windows 目录打开。")
            return
        os.startfile(str(path))

    def _on_close(self) -> None:
        if self._busy_count:
            messagebox.showinfo(APP_NAME, "当前任务尚未结束，请等待任务完成后再关闭。")
            return
        if self._last_state in {
            "starting_capture",
            "waiting_for_game",
            "capturing",
            "draining_capture",
            "analyzing",
            "stop_pending",
        }:
            proceed = messagebox.askyesno(
                APP_NAME,
                "采集仍在进行。关闭前将先停止采集，是否继续？",
            )
            if not proceed:
                return
            try:
                status = request_stop(timeout=30.0)
            except Exception as error:
                messagebox.showerror(APP_NAME, f"停止采集失败，界面将保持打开\n\n{error}")
                return
            if status.get("state") != "stopped":
                messagebox.showerror(
                    APP_NAME,
                    "尚未确认采集器已停止，界面将保持打开。\n\n"
                    + str(status.get("error") or status.get("state") or "未知状态"),
                )
                return
        self.root.destroy()


def _capture_dependency_smoke() -> dict[str, Any]:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    from scapy.sendrecv import AsyncSniffer
    from scapy.utils import PcapNgWriter, PcapReader

    with tempfile.TemporaryDirectory(prefix="yka-smoke-") as temporary_dir:
        capture_path = Path(temporary_dir) / "capture.pcapng"
        writer = PcapNgWriter(str(capture_path))
        try:
            writer.write(Ether() / IP() / TCP() / Raw(load=b"YKA"))
        finally:
            writer.close()
        with PcapReader(str(capture_path)) as reader:
            packet = reader.read_packet()
    return {
        "pcap_roundtrip": packet is not None,
        "async_sniffer": AsyncSniffer.__name__,
    }


def _report_persistence_smoke() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="yka-report-smoke-") as temporary_dir:
        sessions_root = Path(temporary_dir) / "sessions"
        session_dir = sessions_root / "session"
        pcap_dir = session_dir / "pcap"
        pcap_dir.mkdir(parents=True)
        (session_dir / "session.json").write_text("{}", encoding="utf-8")
        (session_dir / "events.jsonl").write_text("", encoding="utf-8")
        (session_dir / "status.json").write_text(
            '{"state":"stopped"}', encoding="utf-8"
        )
        live = build_live_coverage(session_dir)
        final = build_session_report(session_dir)
        capture_path = pcap_dir / "smoke.pcapng"
        capture_path.write_bytes(b"smoke")
        export_path = persist_wechat_export(
            session_dir,
            {
                "schema_version": 1,
                "report_generated_at": final.get("generated_at"),
                "transports": {"raw_json": "[]"},
            },
            sessions_root=sessions_root,
        )
        cleanup = cleanup_session_capture_files(
            session_dir,
            sessions_root=sessions_root,
        )
        report_path = Path(str(final.get("persistence", {}).get("path") or ""))
        return {
            "live_state": live.get("persistence", {}).get("state"),
            "final_state": final.get("persistence", {}).get("state"),
            "report_exists": report_path.is_file(),
            "export_exists": export_path.is_file(),
            "removed_capture_files": cleanup.get("removed_file_count"),
            "capture_removed": not capture_path.exists(),
        }


def _write_smoke_output(path: Path, payload: str) -> None:
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(payload + "\n", encoding="utf-8")
    os.replace(temporary, target)


def is_running_as_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _admin_restart_command() -> tuple[str, list[str]]:
    if getattr(sys, "frozen", False):
        return sys.executable, list(sys.argv[1:])
    return sys.executable, [str(Path(__file__).resolve()), *sys.argv[1:]]


def _launch_elevated(executable: str, arguments: list[str]) -> None:
    parameters = subprocess.list2cmdline(arguments)
    working_directory = (
        Path(executable).resolve().parent
        if getattr(sys, "frozen", False)
        else PROJECT_ROOT
    )
    shell_execute = ctypes.windll.shell32.ShellExecuteW
    shell_execute.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    shell_execute.restype = ctypes.c_void_p
    result = shell_execute(
        None,
        "runas",
        executable,
        parameters,
        str(working_directory),
        1,
    )
    result_code = int(result or 0)
    if result_code <= 32:
        raise OSError(result_code, "Windows 拒绝或取消了管理员权限请求")


def ensure_admin_or_restart() -> bool:
    """Relaunch the normal GUI with UAC; return True in the original process."""
    if os.name != "nt" or is_running_as_admin():
        return False
    executable, arguments = _admin_restart_command()
    _launch_elevated(executable, arguments)
    return True


def _show_native_startup_error(message: str) -> None:
    if os.name == "nt":
        try:
            ctypes.windll.user32.MessageBoxW(None, message, APP_NAME, 0x10)
            return
        except (AttributeError, OSError):
            pass
    print(message, file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="创建界面并立即退出，用于发布验证",
    )
    parser.add_argument("--smoke-output", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--collector-watch", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--session", type=Path, help=argparse.SUPPRESS)
    parser.add_argument(
        "--backend",
        choices=("scapy", "dumpcap"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--interfaces", nargs="+", help=argparse.SUPPRESS)
    parser.add_argument("--interface-names", nargs="+", help=argparse.SUPPRESS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.collector_watch:
        if (
            args.session is None
            or args.backend is None
            or not args.interfaces
            or not args.interface_names
        ):
            raise SystemExit(
                "collector watch requires --session, --backend, --interfaces, "
                "and --interface-names"
            )
        return run_watch(
            args.session,
            args.backend,
            args.interfaces,
            args.interface_names,
        )
    if not args.smoke_test:
        try:
            if ensure_admin_or_restart():
                return 0
        except OSError as error:
            _show_native_startup_error(
                "本程序需要管理员权限才能稳定访问 Npcap 并写入实时报告。\n\n"
                f"{error}"
            )
            return 1
    root = tk.Tk()
    root.withdraw()
    theme = ui_theme.Theme(root)
    if not args.smoke_test and not show_startup_notices(root, theme):
        root.destroy()
        return 0
    app = ReporterApp(root, theme=theme)
    if args.smoke_test:
        root.update_idletasks()
        root.update()
        compact_catalog = load_compact_catalog(
            COMPACT_CATALOG_PATH,
            COMPACT_REGISTRY_PATH,
        )
        smoke_rows = [
            [pool["key"], int(index == 0), 0]
            for index, pool in enumerate(compact_catalog["ordinary"])
        ]
        smoke_rows.extend(
            [background["key"], 0]
            for background in compact_catalog["background"]
        )
        smoke_raw = json.dumps(
            smoke_rows,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        smoke_artifacts = build_import_artifacts(
            smoke_raw,
            catalog_path=COMPACT_CATALOG_PATH,
            registry_path=COMPACT_REGISTRY_PATH,
            target_width=int(compact_catalog["default_width"]),
            expected_pool_keys=tuple(str(row[0]) for row in smoke_rows),
        )
        smoke_qr = {}
        for kind in QR_KINDS:
            image, metadata = export_qr(
                kind,
                smoke_artifacts.qr_payload(kind),
            )
            smoke_qr[kind] = {
                "version": metadata.version,
                "ecc": metadata.error_correction,
                "pixels": image.size[0],
            }
        try:
            scapy_interfaces: dict[str, Any] = {
                "count": len(list_scapy_interfaces())
            }
        except Exception as error:
            scapy_interfaces = {
                "count": 0,
                "error": f"{type(error).__name__}: {error}",
            }
        smoke_payload = json.dumps(
            {
                "app": APP_NAME,
                "version": APP_VERSION,
                "codename": APP_CODENAME,
                "frozen": bool(getattr(sys, "frozen", False)),
                "pool_catalog": POOL_CATALOG_PATH.is_file(),
                "compact_catalog": COMPACT_CATALOG_PATH.is_file(),
                "compact_registry": COMPACT_REGISTRY_PATH.is_file(),
                "qr_kinds": list(QR_KINDS),
                "import_layout": "raw-json + 2x2",
                "compact_codec": smoke_artifacts.codec_id,
                "compact_wire_bytes": len(smoke_artifacts.wire),
                "qr_smoke": smoke_qr,
                "capture_dependencies": _capture_dependency_smoke(),
                "report_persistence": _report_persistence_smoke(),
                "scapy": inspect_scapy(),
                "npcap": inspect_npcap(),
                "scapy_interfaces": scapy_interfaces,
                "sessions_dir": str(SESSIONS_DIR),
                "report_storage": "session/report.json",
                "protocol_spec": PROTOCOL_SPEC_PATH.is_file(),
                "license": LICENSE_PATH.is_file(),
                "startup_notices": len(STARTUP_NOTICES),
            },
            ensure_ascii=True,
        )
        if args.smoke_output is not None:
            _write_smoke_output(args.smoke_output, smoke_payload)
        print(smoke_payload)
        root.destroy()
        return 0
    root.deiconify()
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
