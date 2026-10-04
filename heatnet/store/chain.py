"""分段流水的跨段校验链。

每段滚满时落一个封签边车文件 ``<topic>-NNNNN.seal.json``，记录段号、条数、内容
摘要与上一段的摘要，段与段由此咬合成链：缺段（段号不连续）、改段（内容摘要
对不上封签）、换段（封签里前段摘要与前段实际摘要对不上）都能定位到具体段号。

读取分两种策略，按用途选择：``strict`` 校验不过整段拒读（结算、合规回放的口径）；
``marked`` 给结果标上校验问题后部分读（控制台排查的口径）。

缺失段可以补齐：按段号升序、从已知锚点（前序段封签）连续向后补，候选记录先对
残留封签或后继段封签里的摘要核对，通过才落盘封签。补齐是部分失败语义：单段
失败不拖垮已补的段，``continue_on_error`` 决定首个失败是停（判退）还是继续
（判进）。并发补同一段时后到者判为重复，不覆盖先到的内容。
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from typing import TYPE_CHECKING, Any

from ..errors import StorageError

if TYPE_CHECKING:
    from .journal import JsonlJournal

GENESIS_HASH = "0" * 64
POLICIES = ("strict", "marked")


def digest_records(records: list[dict]) -> str:
    """对一段记录算内容摘要（键序无关的规范 JSON 上取 sha256）。"""

    canonical = json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def normalize_records(records: Any) -> list[dict]:
    """把候选记录规范成可落盘的 JSON 形态，非法形态抛 ``ValueError``。"""

    if not isinstance(records, list):
        raise ValueError("候选记录必须是列表")
    try:
        normalized = json.loads(json.dumps(records, ensure_ascii=False))
    except (TypeError, ValueError) as error:
        raise ValueError(f"候选记录不是可落盘的 JSON: {error}") from error
    if not all(isinstance(item, dict) for item in normalized):
        raise ValueError("候选记录必须逐条是 JSON 对象")
    return normalized


def verify_journal(journal: "JsonlJournal") -> dict:
    """校验整链，返回把每类问题都定位到段号的报告。"""

    indices = journal.segment_indices()
    active = journal.active_segment()
    seals = {index: journal.seal(index) for index in indices}
    missing: list[int] = []
    if indices:
        present = set(indices)
        missing = [index for index in range(indices[-1] + 1) if index not in present]
    tampered: list[int] = []
    unsealed: list[int] = []
    for index in indices:
        seal = seals[index]
        if seal is None:
            # 活动段还在写，不封不验；已完整却没封签的段无法自证，单列出来。
            if index != active:
                unsealed.append(index)
            continue
        records = journal.read_segment(index)
        if seal.get("count") != len(records) or seal.get("hash") != digest_records(records):
            tampered.append(index)
    broken: list[int] = []
    dangling: list[int] = []
    for index in indices:
        seal = seals[index]
        if seal is None:
            continue
        if index == 0:
            if seal.get("prev_hash") != GENESIS_HASH:
                broken.append(index)
            continue
        previous = seals.get(index - 1)
        if previous is None:
            # 前一段缺失或未封签，链条悬在这里；缺段本身已在 missing 里点名。
            dangling.append(index)
            continue
        if seal.get("prev_hash") != previous.get("hash"):
            broken.append(index)
    ok = not (missing or tampered or unsealed or broken)
    return {
        "topic": journal.topic,
        "ok": ok,
        "segments_on_disk": len(indices),
        "active_segment": active,
        "sealed": sum(1 for seal in seals.values() if seal is not None),
        "missing": missing,
        "tampered": tampered,
        "unsealed": unsealed,
        "broken_links": broken,
        "dangling_links": dangling,
    }


def read_segment_verified(journal: "JsonlJournal", index: int, policy: str = "strict") -> dict:
    """按策略读取一段：``strict`` 校验不过整段拒读，``marked`` 标上问题后部分读。"""

    if policy not in POLICIES:
        raise ValueError(f"未知读取策略: {policy}")
    problems: list[str] = []
    records: list[dict] = []
    if index not in journal.segment_indices():
        problems.append("missing")
    else:
        records = journal.read_segment(index)
        seal = journal.seal(index)
        if seal is None:
            problems.append("active_unsealed" if index == journal.active_segment() else "unsealed")
        else:
            if seal.get("count") != len(records):
                problems.append("count_mismatch")
            if seal.get("hash") != digest_records(records):
                problems.append("digest_mismatch")
            if index == 0:
                if seal.get("prev_hash") != GENESIS_HASH:
                    problems.append("chain_broken")
            else:
                previous = journal.seal(index - 1)
                if previous is None:
                    problems.append("chain_dangling")
                elif seal.get("prev_hash") != previous.get("hash"):
                    problems.append("chain_broken")
    if problems and policy == "strict":
        raise StorageError(
            f"段 {index} 校验失败（{', '.join(problems)}），整段拒读", component="store"
        )
    return {
        "segment": index,
        "policy": policy,
        "verified": not problems,
        "problems": problems,
        "records": records,
    }


def _link_segment(path: str, records: list[dict]) -> None:
    """把候选记录无覆盖地落到段文件：先写临时文件，再硬链接占位。

    硬链接在目标已存在时抛 ``FileExistsError``，并发补同一段时后到者据此判重；
    目标路径要么完整出现要么不出现，中途掉电不会留下半截段文件。
    """

    directory = os.path.dirname(path)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, prefix=".fill.", suffix=".tmp", delete=False
    )
    try:
        with handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(handle.name, path)
    finally:
        os.unlink(handle.name)


def backfill_segments(
    journal: "JsonlJournal", fills: dict[int, Any], continue_on_error: bool = False
) -> dict:
    """按段号升序补齐缺失段，逐段先对已知校验值核对再落盘封签。

    返回的报告把补齐结果分成四类：``filled``（补上的）、``failed``（核对或落盘
    失败的）、``duplicates``（已存在或被并发补上的）、``skipped``（判退后未轮到
    的）。``continue_on_error`` 为假时首个失败即停（判退），为真时继续补后续段
    （判进）；已补的段不回滚，``partial`` 标记这是一次部分失败。
    """

    if not isinstance(fills, dict) or not fills:
        raise ValueError("补齐计划必须是非空映射")
    plan: dict[int, list[dict]] = {}
    for raw_index, raw_records in fills.items():
        index = int(raw_index)
        if index < 0:
            raise ValueError("段号不能为负")
        plan[index] = normalize_records(raw_records)

    report: dict[str, Any] = {
        "topic": journal.topic,
        "ok": True,
        "partial": False,
        "aborted": False,
        "continue_on_error": continue_on_error,
        "filled": [],
        "failed": [],
        "duplicates": [],
        "skipped": [],
    }
    active = journal.active_segment()
    order = sorted(plan)
    for position, index in enumerate(order):
        records = plan[index]
        entry: dict[str, Any] = {"segment": index, "records": len(records)}

        def fail(reason: str, **detail: Any) -> None:
            report["failed"].append({**entry, "result": "failed", "reason": reason, **detail})
            if not continue_on_error:
                report["aborted"] = True
                report["skipped"].extend(order[position + 1 :])

        if os.path.isfile(journal.segment_path(index)):
            report["duplicates"].append({**entry, "result": "duplicate", "reason": "already_exists"})
            continue
        if index >= active:
            fail("active_segment")
        elif index > 0 and journal.seal(index - 1) is None:
            # 补齐必须从已知锚点连续向后补，前序段封签缺失时本段无法成链。
            fail("predecessor_missing")
        else:
            own = journal.seal(index)
            successor = journal.seal(index + 1)
            if own is not None:
                basis, expected = "own_seal", own.get("hash")
            elif successor is not None:
                basis, expected = f"successor_seal:{index + 1}", successor.get("prev_hash")
            else:
                basis, expected = "unverifiable", None
            actual = digest_records(records)
            if expected is not None and actual != expected:
                fail("digest_mismatch", expected=expected, actual=actual, basis=basis)
            else:
                try:
                    _link_segment(journal.segment_path(index), records)
                except FileExistsError:
                    report["duplicates"].append(
                        {**entry, "result": "duplicate", "reason": "concurrent_fill"}
                    )
                    continue
                except OSError as error:
                    fail("write_error", error=str(error))
                else:
                    seal = journal.seal(index)
                    if seal is None:
                        seal = journal.seal_segment(index)
                    report["filled"].append(
                        {
                            **entry,
                            "result": "filled",
                            "basis": basis,
                            "hash": seal.get("hash") if seal else actual,
                            "prev_hash": seal.get("prev_hash") if seal else None,
                        }
                    )
        if report["aborted"]:
            break
    journal.rescan()
    healed = journal.seal_complete_segments()
    if healed:
        report["resealed"] = healed
    report["partial"] = bool(report["filled"]) and bool(report["failed"] or report["skipped"])
    report["ok"] = not report["failed"] and not report["skipped"]
    return report
