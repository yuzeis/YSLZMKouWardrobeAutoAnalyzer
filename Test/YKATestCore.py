from __future__ import annotations

import json
from pathlib import Path

import YKACore


def test_atomic_write_json_retries_permission_errors(
    monkeypatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "report.json"
    original_replace = YKACore.os.replace
    attempts = 0

    def flaky_replace(source, destination) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PermissionError("temporarily locked")
        original_replace(source, destination)

    monkeypatch.setattr(YKACore.os, "replace", flaky_replace)
    monkeypatch.setattr(YKACore.time, "sleep", lambda _seconds: None)

    YKACore.atomic_write_json(target, {"state": "live"})

    assert attempts == 3
    assert json.loads(target.read_text(encoding="utf-8")) == {"state": "live"}
    assert not list(tmp_path.glob(".*.tmp"))
