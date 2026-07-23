from __future__ import annotations

from YKAApp import capture_traffic_feedback


def test_generic_flow_does_not_count_as_captured_game_traffic() -> None:
    semantic, label, has_packets = capture_traffic_feedback(
        {
            "state": "capturing",
            "flow_count": 4,
            "capture_packets": 0,
            "capture_has_packets": False,
        }
    )

    assert semantic == "run"
    assert label == "尚未抓到 · 等待目标游戏流量"
    assert has_packets is False


def test_scapy_packet_count_is_shown_exactly() -> None:
    semantic, label, has_packets = capture_traffic_feedback(
        {
            "state": "capturing",
            "capture_packets": 23,
            "capture_packet_count_exact": True,
            "capture_has_packets": True,
        }
    )

    assert semantic == "ok"
    assert label == "已抓到 · 23 个网络包，正在识别游戏协议"
    assert has_packets is True


def test_dumpcap_activity_is_reported_without_fake_packet_count() -> None:
    semantic, label, has_packets = capture_traffic_feedback(
        {
            "state": "capturing",
            "capture_packets": 0,
            "capture_packet_count_exact": False,
            "capture_has_packets": True,
        }
    )

    assert semantic == "ok"
    assert label == "已抓到 · 正在识别游戏协议"
    assert has_packets is True


def test_stopped_session_warns_when_no_game_traffic_was_captured() -> None:
    semantic, label, has_packets = capture_traffic_feedback(
        {
            "state": "stopped",
            "capture_packets": 0,
            "capture_has_packets": False,
        }
    )

    assert semantic == "warn"
    assert label == "未识别 · 本次没有匹配的游戏协议流"
    assert has_packets is False
