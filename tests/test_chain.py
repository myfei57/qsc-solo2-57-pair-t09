"""流水跨段校验链、补段与同轴对齐回放。

覆盖四件事：

1. 链能跨段定位缺段、改段（细到记录位），封段清单与活动尾段实时状态两条
   凭证都要验；严格读法整段拒读，标注读法打上标记后部分读；
2. 补段只补真缺口、顺序不能乱、锚点必须与后段清单一致，同一段并发补两次
   判重复，补段结果直接给 proceed/abort 进退；
3. 审计与趋势按同一条时间轴同轴合并回放，缺段占位、改段标记、趋势补点都在
   时间轴上，结果既给控制台也落审计；
4. 补段与回放动作落审计，审计里能查到补了什么、依据的是哪段校验值。
"""

from __future__ import annotations

import json
import os
import threading

import pytest

from heatnet.audit.replay import ALIGNMENT_COAXIS, build_aligned_replay, fill_series
from heatnet.errors import IntegrityError
from heatnet.store.chain import (
    CHAIN_REASON_KEY,
    CHAIN_SEGMENT_KEY,
    CHAIN_STATUS_KEY,
    POLICY_MARK,
    POLICY_STRICT,
    SegmentChainGuard,
    STATUS_MISSING,
    STATUS_OK,
    STATUS_TAMPERED,
)
from heatnet.store.journal import JsonlJournal


def _rewrite(path, lines):
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)


def test_hash_chain_seals_segments_and_verifies(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    guard = SegmentChainGuard(journal)
    for index in range(5):
        journal.append({"index": index})
    report = guard.verify()
    assert report.ok() is True
    assert [segment.status for segment in report.segments] == [
        STATUS_OK,
        STATUS_OK,
        STATUS_OK,
    ]
    manifests = [name for name in os.listdir(tmp_path) if name.endswith(".chain.json")]
    assert len(manifests) == 2
    records, _ = guard.read_verified(POLICY_STRICT)
    assert [item["index"] for item in records] == [0, 1, 2, 3, 4]
    assert all(item[CHAIN_SEGMENT_KEY] == item["index"] // 2 for item in records)


def test_tampered_record_is_pinpointed_to_segment_and_position(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    guard = SegmentChainGuard(journal)
    for index in range(6):
        journal.append({"index": index})
    path = journal.segment_path(1)
    lines = open(path, encoding="utf-8").read().splitlines(keepends=True)
    bad = json.loads(lines[1])
    bad["index"] = 4096
    lines[1] = json.dumps(bad, ensure_ascii=False) + "\n"
    _rewrite(path, lines)

    report = guard.verify()
    assert report.tampered == (1,)
    segment = report.get(1)
    assert segment.bad_records == (1,)
    assert "position_1" in segment.reason
    with pytest.raises(IntegrityError):
        guard.read_verified(POLICY_STRICT)
    records, marked_report = guard.read_verified(POLICY_MARK)
    assert marked_report.tampered == (1,)
    flagged = [item for item in records if item.get(CHAIN_STATUS_KEY) == STATUS_TAMPERED]
    assert {item["index"] for item in flagged} == {2, 4096}
    pinpointed = [item for item in flagged if "@record_" in item[CHAIN_REASON_KEY]]
    assert pinpointed[0]["index"] == 4096
    assert "position_1@record_1" in pinpointed[0][CHAIN_REASON_KEY]
    good = [item for item in records if item.get(CHAIN_STATUS_KEY) is None]
    assert [item["index"] for item in good] == [0, 1, 4, 5]


def test_active_tail_tamper_is_caught_live_and_after_restart(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=16)
    guard = SegmentChainGuard(journal)
    for index in range(3):
        journal.append({"index": index})
    path = journal.segment_path(0)
    lines = open(path, encoding="utf-8").read().splitlines(keepends=True)
    bad = json.loads(lines[0])
    bad["index"] = 99
    lines[0] = json.dumps(bad, ensure_ascii=False) + "\n"
    _rewrite(path, lines)
    assert guard.verify().tampered == (0,)

    other = tempfile_rolled_then_tampered(tmp_path)
    reopened_guard = SegmentChainGuard(JsonlJournal(str(other), "audit", segment_limit=16))
    assert reopened_guard.verify().tampered == (0,)


def tempfile_rolled_then_tampered(tmp_path):
    root = tmp_path / "restart"
    root.mkdir()
    journal = JsonlJournal(str(root), "audit", segment_limit=16)
    SegmentChainGuard(journal)
    for index in range(3):
        journal.append({"index": index})
    path = journal.segment_path(0)
    lines = open(path, encoding="utf-8").read().splitlines(keepends=True)
    bad = json.loads(lines[2])
    bad["index"] = 77
    lines[2] = json.dumps(bad, ensure_ascii=False) + "\n"
    _rewrite(path, lines)
    return root


def test_missing_segment_is_named_and_marked_with_placeholder(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    guard = SegmentChainGuard(journal)
    for index in range(8):
        journal.append({"index": index})
    saved = journal.read_segment(1)
    os.remove(journal.segment_path(1))

    reopened = SegmentChainGuard(JsonlJournal(str(tmp_path), "audit", segment_limit=2))
    report = reopened.verify()
    assert report.missing == (1,)
    with pytest.raises(IntegrityError):
        reopened.read_verified(POLICY_STRICT)
    records, _ = reopened.read_verified(POLICY_MARK)
    placeholders = [item for item in records if item.get(CHAIN_STATUS_KEY) == STATUS_MISSING]
    assert placeholders and placeholders[0][CHAIN_SEGMENT_KEY] == 1
    return reopened, saved


def test_backfill_requires_order_anchor_and_detects_duplicate(tmp_path):
    reopened, saved = test_missing_segment_is_named_and_marked_with_placeholder(tmp_path)
    wrong = reopened.backfill_segment(1, [{"index": 2}], operator="ops")
    assert wrong["ok"] is False and wrong["status"] == "anchor_mismatch"
    outcome = reopened.backfill_segment(1, saved, operator="ops")
    assert outcome["ok"] is True
    assert outcome["decision"] == "proceed"
    assert outcome["records_installed"] == 2
    assert outcome["anchor_segment"] == 0 and len(outcome["anchor_digest"]) == 64
    assert reopened.verify().ok() is True
    duplicate = reopened.backfill_segment(1, saved, operator="ops2")
    assert duplicate["status"] == "duplicate_applied" and duplicate["decision"] == "abort"
    conflict = reopened.backfill_segment(1, [{"index": 998}, {"index": 999}], operator="ops2")
    assert conflict["status"] == "duplicate_conflict"


def test_backfill_order_cannot_skip_earlier_gaps(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    guard = SegmentChainGuard(journal)
    for index in range(10):
        journal.append({"index": index})
    saved = {index: journal.read_segment(index) for index in (1, 3)}
    os.remove(journal.segment_path(1))
    os.remove(journal.segment_path(3))
    reopened = SegmentChainGuard(JsonlJournal(str(tmp_path), "audit", segment_limit=2))
    skipped = reopened.backfill_segment(3, saved[3])
    assert skipped["status"] == "out_of_order"
    first = reopened.backfill_segment(1, saved[1])
    assert first["status"] == "filled" and first["decision"] == "abort"
    second = reopened.backfill_segment(3, saved[3])
    assert second["status"] == "filled" and second["decision"] == "proceed"


def test_concurrent_backfill_of_same_segment_is_judged_duplicate(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    guard = SegmentChainGuard(journal)
    for index in range(6):
        journal.append({"index": index})
    saved = journal.read_segment(1)
    os.remove(journal.segment_path(1))
    reopened = SegmentChainGuard(JsonlJournal(str(tmp_path), "audit", segment_limit=2))
    barrier = threading.Barrier(2)
    outcomes: list[dict] = []

    def worker() -> None:
        barrier.wait()
        outcomes.append(reopened.backfill_segment(1, saved, operator="thread"))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(item["status"] for item in outcomes) == ["duplicate_applied", "filled"]
    assert sum(item["records_installed"] for item in outcomes) == 2


def test_fill_series_linearly_fills_missing_periods():
    points = fill_series([(0.0, 10.0), (60.0, 40.0)], period_s=30.0)
    assert [point["value"] for point in points] == [10.0, 25.0, 40.0]
    assert [point["filled"] for point in points] == [False, True, False]


def test_aligned_replay_merges_on_one_timeline_with_audit_first():
    audit = [
        {"ts": 10.0, "asset": "a", "component": "c", "action": "x", "severity": "notice",
         "message": "", "payload": {}, CHAIN_SEGMENT_KEY: 0},
        {"ts": 20.0, "asset": "a", "component": "c", "action": "y", "severity": "notice",
         "message": "", "payload": {}, CHAIN_SEGMENT_KEY: 0},
    ]
    trend = [
        {"ts": 10.0, "signal": "supply_c", "value": 60.0, CHAIN_SEGMENT_KEY: 0},
        {"ts": 70.0, "signal": "supply_c", "value": 90.0, CHAIN_SEGMENT_KEY: 0},
    ]
    aligned = build_aligned_replay(audit, trend, period_s=30.0)
    assert aligned["alignment"] == ALIGNMENT_COAXIS
    timeline = aligned["timeline"]
    stamps = [(entry["ts"], entry["axis"]) for entry in timeline]
    assert stamps == sorted(stamps, key=lambda item: (item[0], 0 if item[1] == "audit" else 1))
    at_10 = [entry for entry in timeline if entry["ts"] == 10.0]
    assert [entry["axis"] for entry in at_10] == ["audit", "trend"]
    assert aligned["coverage"]["trend_filled"] == 1
    filled = [
        sample
        for entry in timeline
        if entry["kind"] == "trend"
        for sample in entry["samples"]
        if sample["filled"]
    ]
    assert filled and filled[0]["value"] == 75.0


def test_aligned_replay_places_gap_marker_after_prev_segment(platform):
    platform.start()
    platform.push_weather(-8.0)
    for _ in range(3):
        platform.cycle(dt=30.0)
    trend_path = os.path.join(platform.store.root, "trend-00000.jsonl")
    saved = [json.loads(line) for line in open(trend_path, encoding="utf-8") if line.strip()]
    os.remove(trend_path)
    aligned = platform.replay_aligned(POLICY_MARK)
    gaps = [entry for entry in aligned["timeline"] if entry["kind"] == "gap"]
    assert gaps and gaps[0]["axis"] == "trend" and gaps[0]["segment"] == 0
    assert aligned["decision"] == "abort"
    assert platform.trend_chain.backfill_segment(0, saved)["status"] == "filled"
    healed = platform.replay_aligned(POLICY_MARK)
    assert healed["decision"] == "proceed"
    assert not [entry for entry in healed["timeline"] if entry["kind"] == "gap"]


def test_platform_backfill_and_replay_are_audited(platform):
    platform.start()
    platform.push_weather(-8.0)
    platform.cycle(dt=30.0)
    trend_path = os.path.join(platform.store.root, "trend-00000.jsonl")
    saved = [json.loads(line) for line in open(trend_path, encoding="utf-8") if line.strip()]
    os.remove(trend_path)
    outcome = platform.backfill_segment("trend", 0, saved, operator="ops")
    assert outcome["status"] == "filled"
    platform.replay_aligned(POLICY_MARK)
    actions = {entry.action for entry in platform.audit.records(limit=50)}
    assert "segment_backfill" in actions
    assert "aligned_replay" in actions
    backfill_entry = [
        entry
        for entry in platform.audit.records(limit=50)
        if entry.action == "segment_backfill" and entry.payload.get("ok")
    ][-1]
    assert backfill_entry.payload["journal"] == "trend"
    assert backfill_entry.payload["records_installed"] == len(saved)
    assert backfill_entry.payload["anchor_segment"] == -1
    assert len(backfill_entry.payload["anchor_digest"]) == 64


def test_console_endpoints_expose_chains_backfill_and_replay(platform):
    from heatnet.console.api import Api

    platform.start()
    platform.push_weather(-8.0)
    platform.cycle(dt=30.0)
    api = Api(platform)
    status, chains = api.handle("GET", "/api/chains", {}, {})
    assert status == 200
    assert chains["chains"]["audit"]["ok"] is True
    assert chains["chains"]["trend"]["ok"] is True

    trend_path = os.path.join(platform.store.root, "trend-00000.jsonl")
    saved = [json.loads(line) for line in open(trend_path, encoding="utf-8") if line.strip()]
    os.remove(trend_path)
    status, outcome = api.handle(
        "POST", "/api/backfill", {},
        {"topic": "trend", "segment": 0, "records": saved, "operator": "api"},
    )
    assert status == 200 and outcome["status"] == "filled"
    status, duplicate = api.handle(
        "POST", "/api/backfill", {}, {"topic": "trend", "segment": 0, "records": saved}
    )
    assert status == 200 and duplicate["status"] == "duplicate_applied"
    status, aligned = api.handle("POST", "/api/replay-aligned", {}, {"policy": "strict"})
    assert status == 200 and aligned["alignment"] == ALIGNMENT_COAXIS

    status, bad_segment = api.handle(
        "POST", "/api/backfill", {}, {"topic": "trend", "segment": "nope", "records": []}
    )
    assert status == 400 and bad_segment["error"] == "bad_request"
    status, bad_records = api.handle(
        "POST", "/api/backfill", {}, {"topic": "trend", "segment": 0, "records": "x"}
    )
    assert status == 400
