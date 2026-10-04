"""分段流水的跨段校验链：封签、校验定位、策略读取、补齐与同轴对齐回放。"""

from __future__ import annotations

import os
import threading

import pytest

from heatnet.app import build_platform
from heatnet.audit.record import AuditRecord
from heatnet.clock import ManualClock
from heatnet.config import default_config
from heatnet.console.api import Api
from heatnet.errors import StorageError
from heatnet.store.chain import (
    GENESIS_HASH,
    backfill_segments,
    read_segment_verified,
    verify_journal,
)
from heatnet.store.journal import JsonlJournal


def _fill(journal: JsonlJournal, count: int) -> None:
    for index in range(count):
        journal.append({"index": index})


def _platform(tmp_path, limit: int = 4):
    return build_platform(
        default_config(),
        clock=ManualClock(),
        storage_root=str(tmp_path / "state"),
        audit_segment_limit=limit,
    )


# ---- 封签与校验定位 ---------------------------------------------------


def test_journal_seals_segments_on_roll_and_reopen(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 2)
    assert journal.seal(0) is None
    journal.append({"index": 2})
    seal0 = journal.seal(0)
    assert seal0["count"] == 2
    assert seal0["prev_hash"] == GENESIS_HASH
    _fill(journal, 2)
    seal1 = journal.seal(1)
    assert seal1["prev_hash"] == seal0["hash"]
    reopened = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    assert reopened.seal(0)["hash"] == seal0["hash"]
    assert reopened.seal(1)["hash"] == seal1["hash"]
    assert reopened.seal_complete_segments() == []


def test_verify_clean_chain_is_ok(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 5)
    report = verify_journal(journal)
    assert report["ok"] is True
    assert report["sealed"] == 2
    assert report["active_segment"] == 2
    assert report["missing"] == []


def test_verify_locates_missing_segment(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 8)
    os.remove(journal.segment_path(1))
    os.remove(tmp_path / "audit-00001.seal.json")
    report = verify_journal(journal)
    assert report["ok"] is False
    assert report["missing"] == [1]
    assert report["dangling_links"] == [2]


def test_verify_locates_tampered_segment(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 4)
    with open(journal.segment_path(0), "a", encoding="utf-8") as handle:
        handle.write('{"index": 99}\n')
    report = verify_journal(journal)
    assert report["ok"] is False
    assert report["tampered"] == [0]


def test_verify_locates_broken_link_after_reseal(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 8)
    with open(journal.segment_path(1), "a", encoding="utf-8") as handle:
        handle.write('{"index": 99}\n')
    # 改段并重封能骗过单段核对，但后继段封签里的前段摘要会对不上。
    journal.seal_segment(1)
    report = verify_journal(journal)
    assert report["tampered"] == []
    assert report["broken_links"] == [2]
    assert report["ok"] is False


def test_verify_flags_complete_but_unsealed_segment(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 3)
    os.remove(tmp_path / "audit-00000.seal.json")
    report = verify_journal(journal)
    assert report["unsealed"] == [0]
    assert report["ok"] is False
    reopened = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    assert reopened.seal(0) is not None
    assert verify_journal(reopened)["ok"] is True


# ---- 按策略读取 -------------------------------------------------------


def test_read_policy_strict_rejects_and_marked_marks(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 4)
    with open(journal.segment_path(0), "a", encoding="utf-8") as handle:
        handle.write('{"index": 99}\n')
    with pytest.raises(StorageError):
        read_segment_verified(journal, 0, "strict")
    marked = read_segment_verified(journal, 0, "marked")
    assert marked["verified"] is False
    assert "digest_mismatch" in marked["problems"]
    assert len(marked["records"]) == 3
    with pytest.raises(ValueError):
        read_segment_verified(journal, 0, "unknown-policy")


def test_read_missing_and_active_segment(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 3)
    missing = read_segment_verified(journal, 7, "marked")
    assert missing["verified"] is False
    assert missing["problems"] == ["missing"]
    assert missing["records"] == []
    with pytest.raises(StorageError):
        read_segment_verified(journal, 7, "strict")
    active = read_segment_verified(journal, 1, "marked")
    assert active["problems"] == ["active_unsealed"]
    assert len(active["records"]) == 1


# ---- 缺失段补齐 -------------------------------------------------------


def test_backfill_restores_missing_segment_against_own_seal(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 6)
    records = journal.read_segment(1)
    os.remove(journal.segment_path(1))
    assert verify_journal(journal)["missing"] == [1]
    report = backfill_segments(journal, {1: records})
    assert report["ok"] is True
    assert report["filled"][0]["basis"] == "own_seal"
    assert report["filled"][0]["hash"] == journal.seal(1)["hash"]
    assert verify_journal(journal)["ok"] is True


def test_backfill_against_successor_seal(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 8)
    records = journal.read_segment(1)
    os.remove(journal.segment_path(1))
    os.remove(tmp_path / "audit-00001.seal.json")
    report = backfill_segments(journal, {1: records})
    assert report["ok"] is True
    assert report["filled"][0]["basis"] == "successor_seal:2"
    assert journal.seal(1)["prev_hash"] == journal.seal(0)["hash"]
    assert verify_journal(journal)["ok"] is True


def test_backfill_rejects_digest_mismatch(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 6)
    os.remove(journal.segment_path(1))
    report = backfill_segments(journal, {1: [{"index": 999}]})
    assert report["ok"] is False
    assert report["failed"][0]["reason"] == "digest_mismatch"
    assert not os.path.isfile(journal.segment_path(1))
    assert verify_journal(journal)["missing"] == [1]


def test_backfill_fills_multi_segment_gap_in_order(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 10)
    records1 = journal.read_segment(1)
    records2 = journal.read_segment(2)
    for index in (1, 2):
        os.remove(journal.segment_path(index))
        os.remove(tmp_path / f"audit-{index:05d}.seal.json")
    report = backfill_segments(journal, {2: records2, 1: records1})
    assert [entry["segment"] for entry in report["filled"]] == [1, 2]
    assert journal.seal(2)["prev_hash"] == journal.seal(1)["hash"]
    assert verify_journal(journal)["ok"] is True


def test_backfill_requires_sealed_predecessor(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 10)
    records2 = journal.read_segment(2)
    for index in (1, 2):
        os.remove(journal.segment_path(index))
        os.remove(tmp_path / f"audit-{index:05d}.seal.json")
    report = backfill_segments(journal, {2: records2})
    assert report["failed"][0]["reason"] == "predecessor_missing"
    assert not os.path.isfile(journal.segment_path(2))


def test_backfill_partial_failure_continue_or_abort(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 10)
    records1 = journal.read_segment(1)
    records3 = journal.read_segment(3)
    for index in (1, 2, 3):
        os.remove(journal.segment_path(index))
    plan = {1: records1, 2: [{"index": 999}], 3: records3}
    continued = backfill_segments(journal, dict(plan), continue_on_error=True)
    assert continued["partial"] is True
    assert continued["aborted"] is False
    assert [entry["segment"] for entry in continued["filled"]] == [1, 3]
    assert [entry["segment"] for entry in continued["failed"]] == [2]

    journal2 = JsonlJournal(str(tmp_path / "second"), "audit", segment_limit=2)
    _fill(journal2, 10)
    records1 = journal2.read_segment(1)
    records3 = journal2.read_segment(3)
    for index in (1, 2, 3):
        os.remove(journal2.segment_path(index))
    aborted = backfill_segments(journal2, {1: records1, 2: [{"index": 999}], 3: records3})
    assert aborted["aborted"] is True
    assert [entry["segment"] for entry in aborted["filled"]] == [1]
    assert aborted["skipped"] == [3]
    assert not os.path.isfile(journal2.segment_path(3))


def test_backfill_rejects_active_or_future_segment(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 3)
    report = backfill_segments(journal, {5: [{"index": 0}]})
    assert report["failed"][0]["reason"] == "active_segment"
    with pytest.raises(ValueError):
        backfill_segments(journal, {})
    with pytest.raises(ValueError):
        backfill_segments(journal, {0: "not-a-list"})


def test_backfill_detects_concurrent_duplicate(tmp_path, monkeypatch):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 6)
    records = journal.read_segment(1)
    os.remove(journal.segment_path(1))
    barrier = threading.Barrier(2)
    real_link = os.link

    def gated_link(src, dst):
        barrier.wait(timeout=10)
        return real_link(src, dst)

    monkeypatch.setattr(os, "link", gated_link)
    reports: list[dict] = []

    def worker():
        reports.append(backfill_segments(journal, {1: records}))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(len(report["filled"]) for report in reports) == 1
    assert sum(len(report["duplicates"]) for report in reports) == 1
    reasons = [entry["reason"] for report in reports for entry in report["duplicates"]]
    assert reasons == ["concurrent_fill"]
    assert journal.read_segment(1) == records
    assert verify_journal(journal)["ok"] is True


def test_backfill_existing_segment_is_duplicate(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    _fill(journal, 4)
    report = backfill_segments(journal, {0: [{"index": 0}]})
    assert report["duplicates"][0]["reason"] == "already_exists"
    assert report["filled"] == []


# ---- 平台接线：校验、补齐、对齐回放都落审计 ----------------------------


def test_platform_verify_and_backfill_are_audited(tmp_path):
    platform = _platform(tmp_path)
    for _ in range(10):
        platform.audit.record(AuditRecord.create(platform.clock.now(), "", "ops", "noop"))
    journal = platform.audit.journal
    records = journal.read_segment(1)
    os.remove(journal.segment_path(1))
    report = platform.verify_journal()
    assert report["missing"] == [1]
    assert platform.audit.count("journal_verify") == 1
    result = platform.backfill_journal({1: records})
    assert result["ok"] is True
    assert platform.audit.count("journal_backfill") == 1
    assert platform.audit.count("journal_backfill_summary") == 1
    entries = [item for item in platform.audit.entries(limit=50) if item["action"] == "journal_backfill"]
    assert entries[0]["payload"]["segment"] == 1
    assert entries[0]["payload"]["basis"] == "own_seal"
    assert entries[0]["payload"]["hash"]
    assert platform.verify_journal()["ok"] is True


def test_aligned_replay_merges_audit_and_trend_on_one_axis(tmp_path):
    platform = _platform(tmp_path)
    platform.start()
    platform.push_weather(-8.0)
    platform.cycle(dt=1.0)
    platform.cycle(dt=1.0)
    platform.push_weather(-7.5)
    replay = platform.aligned_replay(slot_s=1.0)
    assert replay["axis"] == "merged"
    slots = replay["slots"]
    assert [slot["slot"] for slot in slots] == sorted(slot["slot"] for slot in slots)
    assert any(slot["audits"] and slot["trends"] for slot in slots)
    assert replay["audits"] > 0
    assert replay["trend_points"] > 0
    assert replay["span"] is not None
    assert platform.audit.count("aligned_replay") == 1


def test_console_chain_endpoints(tmp_path):
    platform = _platform(tmp_path)
    for _ in range(10):
        platform.audit.record(AuditRecord.create(platform.clock.now(), "", "ops", "noop"))
    journal = platform.audit.journal
    records = journal.read_segment(1)
    os.remove(journal.segment_path(1))
    api = Api(platform)
    status, verify = api.handle("GET", "/api/journal/verify", {}, {})
    assert status == 200
    assert verify["ok"] is False
    assert verify["missing"] == [1]
    status, marked = api.handle("GET", "/api/journal/segment/1", {"policy": "marked"}, {})
    assert status == 200
    assert marked["verified"] is False
    assert marked["problems"] == ["missing"]
    status, _payload = api.handle("GET", "/api/journal/segment/1", {}, {})
    assert status == 409
    status, filled = api.handle("POST", "/api/journal/backfill", {}, {"segments": {"1": records}})
    assert status == 200
    assert [entry["segment"] for entry in filled["filled"]] == [1]
    status, verify = api.handle("GET", "/api/journal/verify", {}, {})
    assert verify["ok"] is True
    status, replay = api.handle("GET", "/api/replay", {}, {})
    assert status == 200
    assert replay["axis"] == "merged"
    status, _payload = api.handle("GET", "/api/journal/segment/not-a-number", {}, {})
    assert status == 400
    status, _payload = api.handle("POST", "/api/journal/backfill", {}, {"segments": {}})
    assert status == 400
