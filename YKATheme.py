"""集中式主题模块：颜色、字体、间距与可复用小组件。

设计方向：适配《以闪亮之名》审美的可爱时尚风——珍珠白底、樱花粉主操作、
天空蓝与薄荷绿做信息与成功色、少量香槟金点缀。所有魔法值集中在本文件。
仅依赖 tkinter/ttk；界面不使用 Emoji 或装饰图标。
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

# ---------------------------------------------------------------- 颜色 tokens
COLORS = {
    # 基础
    "app_bg": "#FDFBF7",        # 珍珠白
    "card_bg": "#FFFFFF",
    "card_border": "#EDE3E7",
    "header_bg": "#FFFFFF",
    "header_line": "#E8D9C4",   # 香槟金细线
    "text": "#4A4049",
    "text_soft": "#8A7F88",
    "text_faint": "#B7ACB4",
    # 樱花粉（主操作）
    "pink": "#E88FAD",
    "pink_hover": "#DD7C9E",
    "pink_press": "#C9668C",
    "pink_soft": "#FBEEF3",
    "pink_line": "#F2CBD9",
    "pink_disabled": "#F0D8E1",
    "pink_disabled_fg": "#B9A2AC",
    # 天空蓝（信息 / 运行中）
    "sky": "#5B9BD5",
    "sky_soft": "#EAF3FB",
    "sky_line": "#C6DEF2",
    "sky_text": "#2E6DA4",
    # 薄荷绿（成功）
    "mint": "#4CAF8D",
    "mint_soft": "#E9F7F0",
    "mint_line": "#BFE6D5",
    "mint_text": "#1F7A5C",
    # 香槟金（点缀 / 提示）
    "gold": "#C9A45C",
    "gold_soft": "#FBF4E6",
    "gold_line": "#EAD9B4",
    "gold_text": "#8A6B2C",
    # 警告 / 错误 / 空
    "amber_soft": "#FCF3E2",
    "amber_line": "#EFD9AE",
    "amber_text": "#96690F",
    "rose_soft": "#FBE9EC",
    "rose_line": "#F0C4CC",
    "rose_text": "#B3455A",
    "gray_soft": "#F4F1F3",
    "gray_line": "#E0D9DE",
    # 输入 / 文本区
    "input_bg": "#FFFFFF",
    "input_border": "#E3D7DC",
    "input_focus": "#E88FAD",
    "mono_bg": "#FBF8FA",
    "select_bg": "#F5D4E0",
    # tab
    "tab_bg": "#F6F0F3",
    "tab_fg": "#8A7F88",
    "tab_sel_bg": "#FFFFFF",
    "tab_sel_fg": "#C2557E",
}

# ---------------------------------------------------------------- 间距 tokens
SPACE = {
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 16,
    "xl": 20,
    "page_pad": 16,
    "wrap_margin": 48,  # 自适应 wraplength 的余量
}

MIN_WINDOW = (960, 660)
DEFAULT_WINDOW = "1120x780"

# 语义状态 -> (前景, 底色, 边线)
SEMANTIC = {
    "ok": (COLORS["mint_text"], COLORS["mint_soft"], COLORS["mint_line"]),
    "warn": (COLORS["amber_text"], COLORS["amber_soft"], COLORS["amber_line"]),
    "error": (COLORS["rose_text"], COLORS["rose_soft"], COLORS["rose_line"]),
    "empty": (COLORS["text_soft"], COLORS["gray_soft"], COLORS["gray_line"]),
    "run": (COLORS["sky_text"], COLORS["sky_soft"], COLORS["sky_line"]),
    "idle": (COLORS["text_soft"], COLORS["gray_soft"], COLORS["gray_line"]),
    "gold": (COLORS["gold_text"], COLORS["gold_soft"], COLORS["gold_line"]),
}


def _pick_font_family(root: tk.Misc, preferred: tuple[str, ...]) -> str:
    families = {name.casefold(): name for name in tkfont.families(root)}
    for name in preferred:
        actual = families.get(name.casefold())
        if actual is not None:
            return actual
    return preferred[0]


class Theme:
    """载入宋体/Times New Roman 并配置全部 ttk 样式。"""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.colors = COLORS
        self.space = SPACE
        cjk = _pick_font_family(root, ("宋体", "SimSun"))
        latin = _pick_font_family(root, ("Times New Roman",))
        self.fonts = {
            "body": (cjk, 9),
            "body_bold": (cjk, 9, "bold"),
            "small": (cjk, 8),
            "title": (cjk, 13, "bold"),
            "section": (cjk, 10, "bold"),
            "badge": (cjk, 9, "bold"),
            "latin": (latin, 9),
            "latin_small": (latin, 8),
            "mono": (latin, 9),
        }
        self.font_families = {"cjk": cjk, "latin": latin}
        self.root.option_add("*Font", self.fonts["body"])
        self.root.option_add("*Entry.Font", self.fonts["latin"])
        self.root.option_add("*Text.Font", self.fonts["latin"])
        self._apply_style()

    # ------------------------------------------------------------- ttk 样式
    def _apply_style(self) -> None:
        c, f = self.colors, self.fonts
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        self.root.configure(background=c["app_bg"])
        style.configure(".", font=f["body"], background=c["app_bg"],
                        foreground=c["text"])

        # 容器
        style.configure("TFrame", background=c["app_bg"])
        style.configure("Header.TFrame", background=c["header_bg"])
        style.configure("Card.TFrame", background=c["card_bg"],
                        relief="solid", borderwidth=1,
                        bordercolor=c["card_border"])
        style.configure("CardInner.TFrame", background=c["card_bg"])

        # 文本
        style.configure("TLabel", background=c["app_bg"], foreground=c["text"])
        style.configure("Title.TLabel", background=c["header_bg"],
                        foreground=c["text"], font=f["title"])
        style.configure("Section.TLabel", background=c["card_bg"],
                        foreground=c["text"], font=f["section"])
        style.configure("Body.TLabel", background=c["card_bg"],
                        foreground=c["text"])
        style.configure("Soft.TLabel", background=c["card_bg"],
                        foreground=c["text_soft"])
        style.configure("Footer.TLabel", background=c["app_bg"],
                        foreground=c["text_soft"], font=f["small"])
        style.configure("FooterVersion.TLabel", background=c["app_bg"],
                        foreground=c["text_soft"], font=f["latin_small"])

        # 按钮：主 / 次 / 文字
        style.configure("Primary.TButton", font=f["body_bold"],
                        background=c["pink"], foreground="#FFFFFF",
                        bordercolor=c["pink_press"],
                        lightcolor=c["pink"], darkcolor=c["pink"],
                        focuscolor=c["pink_press"], padding=(16, 8),
                        borderwidth=1)
        style.map("Primary.TButton",
                  background=[("disabled", c["pink_disabled"]),
                              ("pressed", c["pink_press"]),
                              ("active", c["pink_hover"])],
                  foreground=[("disabled", c["pink_disabled_fg"])])

        style.configure("Secondary.TButton", font=f["body"],
                        background=c["card_bg"], foreground=c["text"],
                        bordercolor=c["input_border"],
                        lightcolor=c["card_bg"], darkcolor=c["card_bg"],
                        focuscolor=c["pink"], padding=(13, 7), borderwidth=1)
        style.map("Secondary.TButton",
                  background=[("disabled", c["gray_soft"]),
                              ("pressed", c["pink_line"]),
                              ("active", c["pink_soft"])],
                  foreground=[("disabled", c["text_faint"])],
                  bordercolor=[("focus", c["pink"]),
                               ("active", c["pink_line"])])

        # 标签页
        style.configure("TNotebook", background=c["app_bg"], borderwidth=0,
                        tabmargins=(8, 6, 8, 0))
        style.configure("TNotebook.Tab", font=f["body"],
                        background=c["tab_bg"], foreground=c["tab_fg"],
                        bordercolor=c["card_border"],
                        lightcolor=c["tab_bg"], padding=(18, 8))
        style.map("TNotebook.Tab",
                  background=[("selected", c["tab_sel_bg"])],
                  foreground=[("selected", c["tab_sel_fg"])],
                  font=[("selected", f["body_bold"])],
                  lightcolor=[("selected", c["tab_sel_bg"])],
                  padding=[("selected", (18, 9))],
                  focuscolor=[("focus", c["pink_line"])])

        # 输入
        style.configure("TEntry", font=f["latin"],
                        fieldbackground=c["input_bg"],
                        bordercolor=c["input_border"],
                        lightcolor=c["input_bg"], darkcolor=c["input_bg"],
                        insertcolor=c["text"], padding=(8, 5))
        style.map("TEntry", bordercolor=[("focus", c["input_focus"])])
        style.configure("TSpinbox", font=f["latin"],
                        fieldbackground=c["input_bg"],
                        bordercolor=c["input_border"],
                        lightcolor=c["input_bg"], darkcolor=c["input_bg"],
                        arrowcolor=c["text_soft"], insertcolor=c["text"],
                        padding=(8, 4))
        style.map("TSpinbox", bordercolor=[("focus", c["input_focus"])])

        style.configure("TSeparator", background=c["card_border"])
        style.configure("Card.TSeparator", background=c["card_border"])

        # 进度条（忙碌指示）
        style.configure("Busy.Horizontal.TProgressbar",
                        troughcolor=c["pink_soft"], background=c["pink"],
                        bordercolor=c["pink_line"],
                        lightcolor=c["pink"], darkcolor=c["pink"],
                        thickness=6)

        # 滚动条
        style.configure("TScrollbar", troughcolor=c["app_bg"],
                        background=c["gray_line"],
                        bordercolor=c["app_bg"],
                        arrowcolor=c["text_soft"],
                        lightcolor=c["gray_line"], darkcolor=c["gray_line"])
        style.map("TScrollbar", background=[("active", c["pink_line"])])


# ---------------------------------------------------------------- 组件
class StatusBadge(ttk.Frame):
    """无图标的彩色文字状态徽章。"""

    def __init__(self, parent: tk.Misc, theme: Theme,
                 semantic: str = "idle", text: str = "-") -> None:
        super().__init__(parent, style="CardInner.TFrame")
        self._theme = theme
        self._text_label = tk.Label(self, font=theme.fonts["badge"],
                                    bd=0, padx=0, pady=1, anchor="w")
        self._text_label.pack(side="left", fill="x", expand=True)
        self.set(semantic, text)

    def set(self, semantic: str, text: str) -> None:
        fg, _bg, _line = SEMANTIC.get(semantic, SEMANTIC["idle"])
        card_bg = self._theme.colors["card_bg"]
        self._text_label.configure(text=text, foreground=fg,
                                   background=card_bg)


class Banner(tk.Frame):
    """纯文字提示条（警告 / 信息），使用色底和细边框。"""

    def __init__(self, parent: tk.Misc, theme: Theme, semantic: str,
                 text: str) -> None:
        fg, bg, line = SEMANTIC.get(semantic, SEMANTIC["warn"])
        super().__init__(parent, background=bg, highlightthickness=1,
                         highlightbackground=line)
        self.label = tk.Label(self, text=text, background=bg, foreground=fg,
                              font=theme.fonts["body"], justify="left",
                              anchor="w")
        self.label.pack(side="left", fill="x", expand=True,
                        padx=10, pady=8)
        autowrap(self.label, margin=24)


def card(parent: tk.Misc, theme: Theme, padding: int | None = None) -> ttk.Frame:
    """白色圆角克制卡片（1px 细边框）。返回内容容器。"""
    pad = theme.space["md"] if padding is None else padding
    outer = ttk.Frame(parent, style="Card.TFrame")
    inner = ttk.Frame(outer, style="CardInner.TFrame", padding=pad)
    inner.pack(fill="both", expand=True)
    outer.inner = inner  # type: ignore[attr-defined]
    return outer


def autowrap(label: tk.Widget, margin: int = SPACE["wrap_margin"]) -> None:
    """随容器宽度自适应 wraplength，避免窄窗口下文字被裁切。"""

    def _update(event: tk.Event) -> None:
        width = max(event.width - margin, 160)
        try:
            label.configure(wraplength=width)
        except tk.TclError:
            pass

    parent = label.master
    parent.bind("<Configure>", _update, add="+")


def style_text_widget(widget: tk.Text, theme: Theme, mono: bool = True) -> None:
    """统一 ScrolledText/Text 的观感与选区颜色。"""
    c = theme.colors
    widget.configure(
        font=theme.fonts["mono"] if mono else theme.fonts["body"],
        background=c["mono_bg"], foreground=c["text"],
        insertbackground=c["text"],
        selectbackground=c["select_bg"], selectforeground=c["text"],
        relief="flat", borderwidth=0,
        highlightthickness=1, highlightbackground=c["input_border"],
        highlightcolor=c["input_focus"],
        padx=10, pady=8,
    )


@dataclass(frozen=True)
class MarkdownSpan:
    """A plain-text inline span with one Markdown presentation style."""

    text: str
    style: str = "body"


@dataclass(frozen=True)
class MarkdownBlock:
    """A parsed Markdown block used by the native Tk preview renderer."""

    kind: str
    text: str = ""
    level: int = 0
    marker: str = ""
    language: str = ""
    rows: tuple[tuple[str, ...], ...] = ()


_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_ORDERED_LIST_RE = re.compile(r"^(\s*)(\d+)[.)]\s+(.+)$")
_UNORDERED_LIST_RE = re.compile(r"^(\s*)[-+*]\s+(.+)$")
_TABLE_SEPARATOR_RE = re.compile(r"^:?-{3,}:?$")
_INLINE_RE = re.compile(
    r"(`[^`\n]+`|\*\*[^*\n]+?\*\*|__[^_\n]+?__|"
    r"(?<!\*)\*[^*\n]+?\*(?!\*)|(?<!_)_[^_\n]+?_(?!_))"
)


def parse_markdown_inline(text: str) -> tuple[MarkdownSpan, ...]:
    """Parse the inline styles supported by the protocol preview."""
    spans: list[MarkdownSpan] = []
    cursor = 0
    for match in _INLINE_RE.finditer(text):
        if match.start() > cursor:
            spans.append(MarkdownSpan(text[cursor:match.start()]))
        token = match.group(0)
        if token.startswith("`"):
            spans.append(MarkdownSpan(token[1:-1], "code"))
        elif token.startswith(("**", "__")):
            spans.append(MarkdownSpan(token[2:-2], "strong"))
        else:
            spans.append(MarkdownSpan(token[1:-1], "emphasis"))
        cursor = match.end()
    if cursor < len(text):
        spans.append(MarkdownSpan(text[cursor:]))
    if not spans and text:
        spans.append(MarkdownSpan(text))
    return tuple(spans)


def _split_table_row(line: str) -> tuple[str, ...]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return tuple(cell.strip() for cell in stripped.split("|"))


def _is_table_separator(line: str) -> bool:
    cells = _split_table_row(line)
    return bool(cells) and all(_TABLE_SEPARATOR_RE.fullmatch(cell) for cell in cells)


def _is_horizontal_rule(line: str) -> bool:
    compact = re.sub(r"\s+", "", line)
    return (
        len(compact) >= 3
        and len(set(compact)) == 1
        and compact[0] in "-* _".replace(" ", "")
    )


def _is_block_start(lines: list[str], index: int) -> bool:
    line = lines[index]
    if not line.strip():
        return True
    if line.lstrip().startswith("```"):
        return True
    if _HEADING_RE.match(line) or _is_horizontal_rule(line):
        return True
    if _ORDERED_LIST_RE.match(line) or _UNORDERED_LIST_RE.match(line):
        return True
    if line.lstrip().startswith(">"):
        return True
    return (
        index + 1 < len(lines)
        and "|" in line
        and _is_table_separator(lines[index + 1])
    )


def parse_markdown_blocks(source: str) -> tuple[MarkdownBlock, ...]:
    """Parse the Markdown constructs used by the bundled protocol document."""
    lines = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    blocks: list[MarkdownBlock] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            if blocks and blocks[-1].kind != "blank":
                blocks.append(MarkdownBlock("blank"))
            index += 1
            continue

        if line.lstrip().startswith("```"):
            language = line.lstrip()[3:].strip()
            code_lines: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].lstrip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            if index < len(lines):
                index += 1
            blocks.append(
                MarkdownBlock("code", "\n".join(code_lines), language=language)
            )
            continue

        heading = _HEADING_RE.match(line)
        if heading:
            text = re.sub(r"\s+#+\s*$", "", heading.group(2))
            blocks.append(
                MarkdownBlock("heading", text, level=len(heading.group(1)))
            )
            index += 1
            continue

        if _is_horizontal_rule(line):
            blocks.append(MarkdownBlock("rule"))
            index += 1
            continue

        if (
            index + 1 < len(lines)
            and "|" in line
            and _is_table_separator(lines[index + 1])
        ):
            rows = [_split_table_row(line)]
            column_count = len(rows[0])
            index += 2
            while index < len(lines) and "|" in lines[index] and lines[index].strip():
                row = _split_table_row(lines[index])
                if len(row) != column_count:
                    break
                rows.append(row)
                index += 1
            blocks.append(MarkdownBlock("table", rows=tuple(rows)))
            continue

        ordered = _ORDERED_LIST_RE.match(line)
        unordered = _UNORDERED_LIST_RE.match(line)
        if ordered or unordered:
            match = ordered or unordered
            assert match is not None
            indent = len(match.group(1).expandtabs(4)) // 2
            if ordered:
                marker = f"{ordered.group(2)}."
                text = ordered.group(3)
            else:
                marker = "-"
                text = unordered.group(2) if unordered else ""
            blocks.append(
                MarkdownBlock("list_item", text, level=indent, marker=marker)
            )
            index += 1
            continue

        if line.lstrip().startswith(">"):
            quote_lines: list[str] = []
            while index < len(lines) and lines[index].lstrip().startswith(">"):
                quote_lines.append(lines[index].lstrip()[1:].lstrip())
                index += 1
            blocks.append(MarkdownBlock("quote", " ".join(quote_lines)))
            continue

        paragraph = [stripped]
        index += 1
        while index < len(lines) and not _is_block_start(lines, index):
            paragraph.append(lines[index].strip())
            index += 1
        blocks.append(MarkdownBlock("paragraph", " ".join(paragraph)))

    while blocks and blocks[-1].kind == "blank":
        blocks.pop()
    return tuple(blocks)


def _markdown_plain_text(text: str) -> str:
    return "".join(span.text for span in parse_markdown_inline(text))


def _insert_markdown_inline(
    widget: tk.Text,
    text: str,
    base_tags: tuple[str, ...] = (),
) -> None:
    style_tags = {
        "strong": "md_strong",
        "emphasis": "md_emphasis",
        "code": "md_inline_code",
    }
    for span in parse_markdown_inline(text):
        extra = style_tags.get(span.style)
        tags = base_tags + ((extra,) if extra else ())
        widget.insert("end", span.text, tags)


def _configure_markdown_tags(widget: tk.Text, theme: Theme) -> None:
    colors = theme.colors
    cjk = theme.font_families["cjk"]
    widget.tag_configure(
        "md_body", font=theme.fonts["body"], foreground=colors["text"],
        spacing1=2, spacing3=6,
    )
    widget.tag_configure("md_strong", font=theme.fonts["body_bold"])
    widget.tag_configure("md_emphasis", font=(cjk, 9, "italic"))
    widget.tag_configure(
        "md_inline_code", font=theme.fonts["mono"],
        foreground=colors["rose_text"], background=colors["gray_soft"],
    )
    widget.tag_configure(
        "md_code_block", font=theme.fonts["mono"],
        foreground=colors["text"], background=colors["gray_soft"],
        lmargin1=14, lmargin2=14, rmargin=14, spacing1=8, spacing3=8,
    )
    widget.tag_configure(
        "md_quote", font=theme.fonts["body"], foreground=colors["sky_text"],
        background=colors["sky_soft"], lmargin1=14, lmargin2=14,
        rmargin=14, spacing1=6, spacing3=6,
    )
    widget.tag_configure(
        "md_list_marker", font=theme.fonts["body_bold"],
        foreground=colors["gold_text"],
    )
    for level in range(7):
        left = 14 + level * 18
        widget.tag_configure(
            f"md_list_{level}", lmargin1=left, lmargin2=left + 22,
            spacing1=1, spacing3=2,
        )
    widget.tag_configure(
        "md_rule", foreground=colors["input_border"], justify="center",
        spacing1=7, spacing3=7,
    )
    widget.tag_configure(
        "md_table_header", font=theme.fonts["body_bold"],
        foreground=colors["text"], background=colors["pink_soft"],
    )
    widget.tag_configure("md_table_row", foreground=colors["text"])

    heading_fonts = {
        1: (cjk, 18, "bold"),
        2: (cjk, 14, "bold"),
        3: (cjk, 11, "bold"),
        4: (cjk, 10, "bold"),
        5: (cjk, 9, "bold"),
        6: (cjk, 9, "bold"),
    }
    for level, font in heading_fonts.items():
        widget.tag_configure(
            f"md_h{level}", font=font,
            foreground=colors["pink_press"] if level <= 2 else colors["text"],
            spacing1=12 if level == 1 else 8,
            spacing3=8 if level <= 2 else 4,
        )


def _render_markdown_table(
    widget: tk.Text,
    block: MarkdownBlock,
    theme: Theme,
    table_index: int,
) -> None:
    rows = block.rows
    if not rows:
        return
    column_count = max(len(row) for row in rows)
    measurer = tkfont.Font(root=widget, font=theme.fonts["body"])
    widths: list[int] = []
    for column in range(column_count - 1):
        measured = max(
            measurer.measure(_markdown_plain_text(row[column]))
            for row in rows
            if column < len(row)
        )
        widths.append(max(72, min(measured + 28, 340)))
    tabs: list[int | str] = []
    position = 14
    for width in widths:
        position += width
        tabs.extend((position, "left"))
    table_tag = f"md_table_{table_index}"
    widget.tag_configure(
        table_tag, font=theme.fonts["body"], tabs=tuple(tabs),
        lmargin1=12, lmargin2=12, rmargin=12, spacing1=3, spacing3=3,
    )
    for row_index, row in enumerate(rows):
        row_tag = "md_table_header" if row_index == 0 else "md_table_row"
        for column, cell in enumerate(row):
            if column:
                widget.insert("end", "\t", (table_tag, row_tag))
            _insert_markdown_inline(widget, cell, (table_tag, row_tag))
        widget.insert("end", "\n", (table_tag, row_tag))


def render_markdown(widget: tk.Text, source: str, theme: Theme) -> None:
    """Render Markdown into a read-only Tk Text widget without HTML dependencies."""
    style_text_widget(widget, theme, mono=False)
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    _configure_markdown_tags(widget, theme)
    previous_kind = ""
    table_index = 0
    for block in parse_markdown_blocks(source):
        if block.kind == "blank":
            if previous_kind and widget.get("end-2c", "end-1c") != "\n":
                widget.insert("end", "\n")
            previous_kind = block.kind
            continue
        if block.kind == "heading":
            tag = f"md_h{max(1, min(block.level, 6))}"
            _insert_markdown_inline(widget, block.text, (tag,))
            widget.insert("end", "\n", (tag,))
        elif block.kind == "paragraph":
            _insert_markdown_inline(widget, block.text, ("md_body",))
            widget.insert("end", "\n", ("md_body",))
        elif block.kind == "code":
            widget.insert("end", block.text + "\n", ("md_code_block",))
        elif block.kind == "quote":
            _insert_markdown_inline(widget, block.text, ("md_quote",))
            widget.insert("end", "\n", ("md_quote",))
        elif block.kind == "list_item":
            level = max(0, min(block.level, 6))
            list_tag = f"md_list_{level}"
            widget.insert("end", block.marker + "  ", (list_tag, "md_list_marker"))
            _insert_markdown_inline(widget, block.text, (list_tag,))
            widget.insert("end", "\n", (list_tag,))
        elif block.kind == "table":
            _render_markdown_table(widget, block, theme, table_index)
            table_index += 1
        elif block.kind == "rule":
            widget.insert("end", "-" * 72 + "\n", ("md_rule",))
        previous_kind = block.kind
    widget.configure(state="disabled")
