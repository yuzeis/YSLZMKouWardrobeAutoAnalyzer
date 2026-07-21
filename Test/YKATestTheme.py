from __future__ import annotations

from pathlib import Path

from YKATheme import parse_markdown_blocks, parse_markdown_inline


def test_markdown_inline_styles_remove_source_markers() -> None:
    spans = parse_markdown_inline("普通 **加粗** *斜体* 和 `wire`。")
    assert [(span.text, span.style) for span in spans] == [
        ("普通 ", "body"),
        ("加粗", "strong"),
        (" ", "body"),
        ("斜体", "emphasis"),
        (" 和 ", "body"),
        ("wire", "code"),
        ("。", "body"),
    ]


def test_markdown_blocks_parse_headings_lists_tables_and_code() -> None:
    source = """# 标题

1. 第一项
2. 第二项

| 字段 | 说明 |
|---|---|
| id | `catalog_id` |

```text
wire = header + payload
```
"""
    blocks = parse_markdown_blocks(source)
    assert blocks[0].kind == "heading"
    assert blocks[0].text == "标题"
    assert [block.marker for block in blocks if block.kind == "list_item"] == [
        "1.",
        "2.",
    ]
    table = next(block for block in blocks if block.kind == "table")
    assert table.rows == (("字段", "说明"), ("id", "`catalog_id`"))
    code = next(block for block in blocks if block.kind == "code")
    assert code.language == "text"
    assert code.text == "wire = header + payload"


def test_bundled_protocol_uses_supported_markdown_blocks() -> None:
    spec_path = Path(__file__).resolve().parents[1] / "Docs" / "YKAProtocolSpec.md"
    blocks = parse_markdown_blocks(spec_path.read_text(encoding="utf-8"))
    kinds = {block.kind for block in blocks}
    assert {"heading", "paragraph", "list_item", "table", "code", "rule"} <= kinds
    assert sum(block.kind == "heading" for block in blocks) >= 40
    assert sum(block.kind == "table" for block in blocks) >= 3
    assert sum(block.kind == "code" for block in blocks) >= 20
