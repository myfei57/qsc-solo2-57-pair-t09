"""流水段的跨段校验链。

每段 JSONL 落盘后都无法单独自证完整，缺段、改段在事后复盘时只能靠人对。
:class:`SegmentChainGuard` 在不动数据文件的前提下给流水套两层哈希链：

* **记录链（跨段不断）**：
  ``record_hash_n = sha256(record_hash_{n-1} || 规范字节_n)``，上一段末条记录
  的哈希就是下一段第一条记录的前缀。改掉任意一字节，该记录及其后每条记录的
  哈希立刻对不上，校验时直接报出"哪一段的第几条"；
* **段锚点（段与段绑定）**：封段时写旁车清单
  ``<topic>-<段号>.chain.json``，其中 ``digest = sha256(上一段 digest ‖
  本段末条记录哈希)``，把本段内容和上一段锚死；段号连续性也在逐段校验时核对。

活动尾段还没封死，没有清单凭证：进程内每次追加都增量推进一份实时链状态旁车
``<topic>.chain.live``，所以尾段在运行期、以及重启后都照样可验，篡改尾段同样
报具体记录位。

读法按用途分两档，并在本模块定死，不允许调用方临时含糊：

* :data:`POLICY_STRICT`（恢复用途）：链上只要存在缺段/改段/未锚定旧段，整段
  拒读，直接抛 :class:`..errors.IntegrityError`；
* :data:`POLICY_MARK`（控制台复盘）：好段原样返回，坏段里能解析的记录照样
  返回，但每条都打上 ``chain_status``/``chain_reason``，缺段在结果里留占位。

补段 (:meth:`SegmentChainGuard.backfill_segment`) 只补经校验确认的真缺口，
顺序不能跨过更前面的缺口，内容必须同时与前一段末条记录哈希、后一段清单的
``prev_digest`` 对得上；返回里的 ``decision`` 直接给进退（``proceed`` /
``abort``），同一段并发补两次判重复，绝不覆盖已有段。

对齐方式同样在本模块定死：审计与趋势各自一条链，回放时按同一条时间轴同轴
合并（见 :mod:`..audit.replay`），不存在"各轴独立"的第二条口径。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Callable

from ..errors import IntegrityError, StorageError

POLICY_STRICT = "strict"
POLICY_MARK = "mark"
POLICIES = (POLICY_STRICT, POLICY_MARK)

STATUS_OK = "ok"
STATUS_MISSING = "missing"
STATUS_TAMPERED = "tampered"
STATUS_DERIVED = "derived"
STATUS_UNSEALED = "unsealed"

GENESIS = "0" * 64
CHAIN_VERSION = 1

CHAIN_STATUS_KEY = "chain_status"
CHAIN_REASON_KEY = "chain_reason"
CHAIN_SEGMENT_KEY = "chain_segment"


@dataclass(frozen=True)
class SegmentReport:
    """一个段在链校验里的结论。"""

    index: int
    status: str
    record_count: int = 0
    manifest_count: int | None = None
    digest: str | None = None
    manifest_digest: str | None = None
    prev_digest: str | None = None
    expected_prev_digest: str | None = None
    reason: str = ""
    sealed: bool = True
    bad_records: tuple[int, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        data = asdict(self)
        data["bad_records"] = list(self.bad_records)
        return data


@dataclass(frozen=True)
class ChainReport:
    """整条链的校验结论。"""

    topic: str
    highest_index: int
    segments: tuple[SegmentReport, ...]
    missing: tuple[int, ...]
    tampered: tuple[int, ...]
    derived: tuple[int, ...]

    def as_dict(self) -> dict:
        return {
            "topic": self.topic,
            "highest_index": self.highest_index,
            "ok": self.ok(),
            "proceed": self.proceed(),
            "missing": list(self.missing),
            "tampered": list(self.tampered),
            "derived": list(self.derived),
            "segments": [segment.as_dict() for segment in self.segments],
        }

    def get(self, index: int) -> SegmentReport | None:
        for segment in self.segments:
            if segment.index == index:
                return segment
        return None

    def ok(self) -> bool:
        """链是否完整可信（无缺段、无改段、无未锚定的旧段）。"""

        return not self.missing and not self.tampered and not self.derived

    def proceed(self) -> bool:
        """补段/复盘后是否允许继续：链必须完整可信，活动尾段可未封。"""

        return self.ok()


def canonical_bytes(record: dict) -> bytes:
    """记录的规范字节：键排序、无空白，保证写盘与重算字节一致。"""

    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def record_hash(previous: str, record: dict) -> str:
    """滚动计算一条记录的哈希，前一条哈希把本条与整条记录链绑死。"""

    digest = hashlib.sha256()
    digest.update(previous.encode("ascii"))
    digest.update(canonical_bytes(record))
    return digest.hexdigest()


def fold_records(records: list[dict], record_anchor: str) -> tuple[str, tuple[str, ...]]:
    """按记录链连续折叠，返回 (末条记录哈希, 各记录哈希)。

    ``record_anchor`` 是上一段末条记录哈希，首段取创世值；记录链跨段不断，
    段边界不重置前缀。
    """

    previous = record_anchor
    hashes: list[str] = []
    for item in records:
        previous = record_hash(previous, item)
        hashes.append(previous)
    return previous, tuple(hashes)


def segment_digest(segment_anchor: str, last_record_hash: str) -> str:
    """段摘要：把本段末条记录哈希与上一段段摘要锚在一起。"""

    return hashlib.sha256(
        segment_anchor.encode("ascii") + last_record_hash.encode("ascii")
    ).hexdigest()


def compare_record_hashes(actual: tuple[str, ...], manifest: tuple[str, ...]) -> tuple[int, ...]:
    """逐记录比对重算哈希与清单哈希，返回所有不符的记录位（含被删的尾记录）。"""

    bad: list[int] = []
    for position, value in enumerate(actual):
        if position >= len(manifest) or value != manifest[position]:
            bad.append(position)
    if len(manifest) > len(actual):
        bad.extend(range(len(actual), len(manifest)))
    return tuple(bad)


@dataclass(frozen=True)
class _Anchors:
    """一个段续链需要的两个前缀。"""

    segment_anchor: str
    record_anchor: str


class SegmentChainGuard:
    """给一条分段落盘流水挂跨段哈希链并负责校验与补段。"""

    def __init__(self, journal) -> None:
        self._journal = journal
        self._topic = journal.topic
        self._root = journal.root
        journal.add_sealed_listener(self._on_segment_sealed)
        journal.add_append_listener(self._on_record_appended)
        self._backfill_locks: dict[int, threading.Lock] = {}
        self._materialize_legacies()
        self._live = self._init_live_state()

    @property
    def journal(self):
        return self._journal

    # ---- 旁车文件 -----------------------------------------------------

    def manifest_path(self, index: int) -> str:
        return os.path.join(self._root, f"{self._topic}-{index:05d}.chain.json")

    def live_path(self) -> str:
        # 用 .live 结尾而不是 .json，避免被 JsonStore 当成当前态文档列出来。
        return os.path.join(self._root, f"{self._topic}.chain.live")

    def _atomic_write(self, target: str, payload: dict, kind: str, index: int | None) -> None:
        directory = os.path.dirname(target)
        suffix = f".{index:05d}" if index is not None else ""
        try:
            handle = tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=directory,
                prefix=f".{self._topic}{suffix}.{kind}.",
                delete=False,
            )
            with handle:
                json.dump(payload, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, target)
        except OSError as error:
            raise StorageError(f"写入链旁车 {kind}{suffix} 失败: {error}", component="store") from error

    def _write_manifest(self, index: int, payload: dict) -> None:
        self._atomic_write(self.manifest_path(index), payload, "chain", index)

    def _write_live(self) -> None:
        self._atomic_write(self.live_path(), self._live, "live", None)

    def _load_manifest(self, index: int) -> dict | None:
        path = self.manifest_path(index)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def _load_live(self) -> dict:
        path = self.live_path()
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _build_manifest_payload(
        self,
        index: int,
        records: list[dict],
        anchors: _Anchors,
        *,
        origin: str = "sealed",
        operator: str = "",
    ) -> dict:
        last_hash, hashes = fold_records(records, anchors.record_anchor)
        payload = {
            "version": CHAIN_VERSION,
            "topic": self._topic,
            "segment": index,
            "record_count": len(records),
            "prev_digest": anchors.segment_anchor,
            "record_anchor": anchors.record_anchor,
            "digest": segment_digest(anchors.segment_anchor, last_hash),
            "last_record_hash": last_hash,
            "record_hashes": list(hashes),
            "origin": origin,
        }
        if origin == "backfill":
            payload["backfill_of"] = index
            payload["operator"] = operator
        return payload

    # ---- 锚点推导 -----------------------------------------------------

    def _anchors_before(self, index: int) -> _Anchors:
        """取 index 段续链所需的两个前缀：上一段段摘要与上一段末条记录哈希。"""

        payload = self._load_manifest(index - 1)
        if payload is not None:
            return _Anchors(
                segment_anchor=str(payload.get("digest", GENESIS)),
                record_anchor=str(payload.get("last_record_hash", GENESIS)),
            )
        return _Anchors(segment_anchor=GENESIS, record_anchor=GENESIS)

    def _materialize_legacies(self) -> None:
        """为升级前遗留、已封死但没清单的连续段补建派生清单。

        派生链从创世值连续折叠，内容自洽但没有原始封段凭证，校验时标
        :data:`STATUS_DERIVED` 而不是伪装成原生可信段；遇到第一个缺口就停，
        缺口之后的段不替它伪造锚点。
        """

        with self._journal.lock:
            indices = self._scan_indices()
            if not indices:
                return
            active = self._journal.active_segment()
            for index in range(max(indices) + 1):
                if not os.path.isfile(self._journal.segment_path(index)):
                    break
                if self._load_manifest(index) is not None or index >= active:
                    continue
                records = self._safe_read(index)
                anchors = self._anchors_before(index)
                self._write_manifest(
                    index,
                    self._build_manifest_payload(index, records, anchors, origin="derived"),
                )

    def _on_segment_sealed(self, topic: str, index: int) -> None:
        if topic != self._topic:
            return
        with self._journal.lock:
            # 活动尾段补段后又继续追加过：旧清单记的是补齐那一刻的短段，封段时
            # 必须以最终内容重签，不能让过期清单与同号数据文件并存。
            stale = self.manifest_path(index)
            if os.path.isfile(stale):
                try:
                    os.remove(stale)
                except OSError as error:
                    raise StorageError(f"清理过期段清单 {index} 失败: {error}", component="store") from error
            records = self._safe_read(index)
            anchors = self._anchors_before(index)
            self._write_manifest(
                index,
                self._build_manifest_payload(index, records, anchors, origin="sealed"),
            )

    def _init_live_state(self, force_rebuild: bool = False) -> dict:
        """恢复或新建活动尾段的实时链状态。

        上一进程把实时哈希落进了 live 旁车：它仍指向当前活动段且无需强制重建时
        以它为准核对文件（进程外篡改此刻暴露）；活动段已滚过、旁车滞后，或补段
        修复了尾段之前的缺口（``force_rebuild``）时，从最后一个封死清单重新折叠。
        """

        active = self._journal.active_segment()
        records = self._safe_read(active)
        stored = self._load_live()
        current = (
            stored
            if not force_rebuild
            and stored.get("topic") == self._topic
            and int(stored.get("segment", -1)) == active
            else None
        )
        if current is not None:
            live = dict(current)
        else:
            anchors = self._anchors_before(active)
            live = self._live_payload(active, records, anchors)
        self._live = live
        self._write_live()
        return live

    def _live_payload(self, index: int, records: list[dict], anchors: _Anchors) -> dict:
        last_hash, hashes = fold_records(records, anchors.record_anchor)
        return {
            "version": CHAIN_VERSION,
            "topic": self._topic,
            "segment": index,
            "count": len(records),
            "prev_digest": anchors.segment_anchor,
            "record_anchor": anchors.record_anchor,
            "last_record_hash": last_hash,
            "digest": segment_digest(anchors.segment_anchor, last_hash),
            "record_hashes": list(hashes),
        }

    def _on_record_appended(self, topic: str, index: int, record: dict) -> None:
        if topic != self._topic:
            return
        with self._journal.lock:
            same_segment = int(self._live.get("segment", -1)) == index
            if same_segment:
                segment_anchor = str(self._live.get("prev_digest", GENESIS))
                record_anchor = str(self._live.get("last_record_hash", GENESIS))
                hashes = list(self._live.get("record_hashes", []))
            else:
                anchors = self._anchors_before(index)
                segment_anchor, record_anchor = anchors.segment_anchor, anchors.record_anchor
                hashes = []
            new_hash = record_hash(record_anchor, record)
            hashes.append(new_hash)
            extends_manifest = same_segment and self._load_manifest(index) is not None
            if extends_manifest:
                # 补段清单只锁了补齐那一刻的短段；继续追加后活动段比清单长，
                # 实时记录哈希必须覆盖整段文件：从该段基锚点把全部记录重折一遍。
                backfill_manifest = self._load_manifest(index)
                base_anchor = (
                    str(backfill_manifest.get("record_anchor", GENESIS))
                    if backfill_manifest is not None
                    else str(self._live.get("record_anchor", GENESIS))
                )
                records_now = self._safe_read(index)
                last_full, hashes = fold_records(records_now, base_anchor)
                new_hash = last_full
            self._live = {
                "version": CHAIN_VERSION,
                "topic": self._topic,
                "segment": index,
                "count": len(hashes),
                "prev_digest": segment_anchor,
                "record_anchor": base_anchor if extends_manifest else record_anchor,
                "last_record_hash": new_hash,
                "digest": segment_digest(segment_anchor, new_hash),
                "record_hashes": hashes,
                # 活动尾段可能已经持有补段清单：继续追加时它事实上又变回"未封死"
                # 状态，标记一下，让校验不要拿旧清单去套已经变长的段。
                "extends_manifest": extends_manifest,
            }
            self._write_live()

    # ---- 扫描与逐段校验 ----------------------------------------------

    def _scan_indices(self) -> list[int]:
        pattern = re.compile(rf"^{re.escape(self._topic)}-(\d{{5}})\.jsonl$")
        indices: list[int] = []
        try:
            names = os.listdir(self._root)
        except OSError:
            return []
        for name in names:
            match = pattern.match(name)
            if match:
                indices.append(int(match.group(1)))
        return sorted(set(indices))

    def _safe_read(self, index: int) -> list[dict]:
        try:
            return self._journal.read_segment(index)
        except StorageError:
            return []

    def _verify_index(self, index: int, expected_prev: str) -> SegmentReport:
        data_path = self._journal.segment_path(index)
        manifest = self._load_manifest(index)
        if not os.path.isfile(data_path):
            return SegmentReport(
                index=index,
                status=STATUS_MISSING,
                manifest_digest=str(manifest["digest"]) if manifest else None,
                expected_prev_digest=expected_prev,
                reason="segment_file_missing",
            )
        try:
            records = self._journal.read_segment(index)
        except StorageError as error:
            return SegmentReport(
                index=index,
                status=STATUS_TAMPERED,
                manifest_count=(manifest or {}).get("record_count"),
                manifest_digest=str(manifest["digest"]) if manifest else None,
                expected_prev_digest=expected_prev,
                reason=f"unreadable: {error.message}",
            )

        sealed = index < self._journal.active_segment()
        # 活动尾段在补段后会持有清单，但一旦继续追加，段已经比清单记录的更长，
        # 此刻以实时链状态为准；封死段（index < active）永远以清单为准。
        live_overrides = (
            not sealed
            and int(self._live.get("segment", -1)) == index
            and bool(self._live.get("extends_manifest"))
        )
        witness = None if live_overrides else manifest
        if witness is None and not sealed and int(self._live.get("segment", -1)) == index:
            witness = self._live
        if witness is None:
            anchors = self._anchors_before(index)
            last_hash, _hashes = fold_records(records, anchors.record_anchor)
            status = STATUS_UNSEALED if not sealed else STATUS_DERIVED
            return SegmentReport(
                index=index,
                status=status,
                record_count=len(records),
                digest=segment_digest(anchors.segment_anchor, last_hash),
                expected_prev_digest=expected_prev,
                reason="active_segment_not_sealed" if status == STATUS_UNSEALED else "derived_legacy_segment",
                sealed=False,
            )

        witness_prev = str(witness.get("prev_digest", GENESIS))
        # 记录链跨段不断：
        # * 封死清单按它封存时自带的 record_anchor 快照重算；
        # * 普通活动尾段从上一段旁车的末条记录哈希续着重算；
        # * 补段后又继续追加的活动尾段，从它记录的补段清单锚点续着算。
        prior = self._load_manifest(index - 1)
        if prior is None and int(self._live.get("segment", -1)) == index - 1:
            prior = self._live
        prior_tail = (
            str(prior.get("last_record_hash", GENESIS)) if prior is not None else GENESIS
        )
        if live_overrides:
            # 段已比补段清单长：实时状态里的 record_hashes 始终是从该段基锚点
            # （补段清单的 record_anchor）对整段文件连续折叠的结果，按基锚点
            # 重算整段即可，清单只负责锁定它被补齐那一刻的前 12 条。
            fold_anchor = str(witness.get("record_anchor", GENESIS))
        elif manifest is None:
            fold_anchor = prior_tail
        else:
            fold_anchor = str(witness.get("record_anchor", GENESIS))
        witness_hashes = tuple(witness.get("record_hashes", []))
        witness_count = witness.get("count") if witness is self._live else witness.get("record_count")
        witness_digest = str(witness.get("digest", ""))
        actual_last, actual_hashes = fold_records(records, fold_anchor)
        # 段摘要恒为 sha256(本段段锚点 ‖ 本段末条记录哈希)；活动尾段的段锚点
        # 就是上一段的段摘要，和封死清单口径一致。
        actual_digest = segment_digest(witness_prev, actual_last)
        bad_records = compare_record_hashes(actual_hashes, witness_hashes)
        count_bad = witness_count is not None and int(witness_count) != len(records)
        digest_bad = actual_digest != witness_digest
        if bad_records or count_bad or digest_bad:
            if bad_records:
                reason = f"record_hash_mismatch_from_position_{bad_records[0]}"
            elif count_bad:
                reason = "record_count_mismatch"
            else:
                reason = "segment_digest_mismatch"
            return SegmentReport(
                index=index,
                status=STATUS_TAMPERED,
                record_count=len(records),
                manifest_count=int(witness_count) if witness_count is not None else None,
                digest=actual_digest,
                manifest_digest=witness_digest,
                prev_digest=witness_prev,
                expected_prev_digest=expected_prev,
                reason=reason,
                sealed=manifest is not None,
                bad_records=bad_records,
            )
        if witness_prev != expected_prev:
            return SegmentReport(
                index=index,
                status=STATUS_TAMPERED,
                record_count=len(records),
                manifest_count=int(witness_count) if witness_count is not None else None,
                digest=actual_digest,
                manifest_digest=witness_digest,
                prev_digest=witness_prev,
                expected_prev_digest=expected_prev,
                reason="prev_digest_anchor_mismatch",
                sealed=manifest is not None,
            )
        return SegmentReport(
            index=index,
            status=STATUS_OK,
            record_count=len(records),
            manifest_count=int(witness_count) if witness_count is not None else None,
            digest=actual_digest,
            manifest_digest=witness_digest,
            prev_digest=witness_prev,
            expected_prev_digest=expected_prev,
            sealed=manifest is not None,
        )

    def verify(self) -> ChainReport:
        """按段号逐段跨段校验，缺段、改段、派生段全部报出具体段号。"""

        with self._journal.lock:
            data_indices = self._scan_indices()
            manifest_indices = [
                index
                for name in os.listdir(self._root)
                if (index := self._manifest_index(name)) is not None
            ]
            # 活动尾段即便文件被运行期删掉也在链范围内：实时链状态里记着它；
            # 但从未写过数据的空段（count==0）不算缺口，只追加过的段才受链保护。
            live_index = int(self._live.get("segment", -1)) if self._live else -1
            if live_index >= 0 and int(self._live.get("count", 0)) == 0:
                live_index = -1
            highest = max(data_indices + manifest_indices + [live_index], default=-1)
            reports: list[SegmentReport] = []
            expected = GENESIS
            for index in range(highest + 1):
                report = self._verify_index(index, expected)
                reports.append(report)
                manifest = self._load_manifest(index)
                if manifest is not None:
                    expected = str(manifest.get("digest", expected))
                elif report.status == STATUS_OK and report.digest:
                    expected = report.digest
            missing = tuple(item.index for item in reports if item.status == STATUS_MISSING)
            tampered = tuple(item.index for item in reports if item.status == STATUS_TAMPERED)
            derived = tuple(item.index for item in reports if item.status == STATUS_DERIVED)
            return ChainReport(
                topic=self._topic,
                highest_index=highest,
                segments=tuple(reports),
                missing=missing,
                tampered=tampered,
                derived=derived,
            )

    def _manifest_index(self, name: str) -> int | None:
        match = re.match(rf"^{re.escape(self._topic)}-(\d{{5}})\.chain\.json$", name)
        return int(match.group(1)) if match else None

    # ---- 带校验读法 ---------------------------------------------------

    def read_verified(
        self, policy: str = POLICY_MARK, limit: int | None = None
    ) -> tuple[list[dict], ChainReport]:
        """按策略读取全链记录。

        ``strict``：链不完整可信即抛 :class:`IntegrityError`，整段拒读，恢复用途
        用；``mark``：好段原样返回（带来源段号），坏段可解析的记录打上状态标记，
        缺段给占位。
        """

        if policy not in POLICIES:
            raise ValueError(f"未知的链读法: {policy}")
        with self._journal.lock:
            report = self.verify()
            if policy == POLICY_STRICT and not report.ok():
                raise IntegrityError(self._describe_failure(report), component="store")
            records: list[dict] = []
            for segment in report.segments:
                if segment.status == STATUS_MISSING:
                    records.append(
                        {
                            CHAIN_SEGMENT_KEY: segment.index,
                            CHAIN_STATUS_KEY: STATUS_MISSING,
                            CHAIN_REASON_KEY: segment.reason,
                        }
                    )
                    continue
                raw = self._safe_read(segment.index)
                bad_positions = set(segment.bad_records)
                for position, item in enumerate(raw):
                    stamped = dict(item)
                    stamped[CHAIN_SEGMENT_KEY] = segment.index
                    if segment.status != STATUS_OK:
                        stamped[CHAIN_STATUS_KEY] = segment.status
                        stamped[CHAIN_REASON_KEY] = (
                            f"{segment.reason}@record_{position}"
                            if position in bad_positions
                            else segment.reason
                        )
                    records.append(stamped)
            if limit is not None:
                records = records[-int(limit) :]
            return records, report

    @staticmethod
    def _describe_failure(report: ChainReport) -> str:
        parts: list[str] = []
        if report.missing:
            parts.append(f"缺段 {list(report.missing)}")
        if report.tampered:
            details = [
                f"{segment.index}({segment.reason})"
                for segment in report.segments
                if segment.status == STATUS_TAMPERED
            ]
            parts.append(f"改段 {details}")
        if report.derived:
            parts.append(f"未锚定旧段 {list(report.derived)}")
        return f"流水 {report.topic} 跨段校验不过: {'; '.join(parts)}"

    # ---- 补段 ---------------------------------------------------------

    def backfill_segment(
        self,
        index: int,
        records: list[dict],
        *,
        operator: str = "console",
        now: Callable[[], float] | None = None,
    ) -> dict:
        """补齐一个缺失段，顺序、锚点、并发重复全部在此判死。

        * 只能补链校验确认为缺段的段号；已经存在（含刚被并发补上）一律判重复；
        * 补段顺序不能乱：该段之前不允许还有没补齐的缺口；
        * 内容必须同时与前一段末条记录哈希、后一段清单声明的两个锚点对得上，
          否则拒装。

        返回里的 ``decision`` 直接给出进退：``proceed`` 可继续，``abort``
        必须中止；补齐本身只算部分失败，调用方据此判进退而不是靠异常猜。
        """

        with self._journal.lock:
            report = self.verify()
            current = report.get(index)
            if current is None:
                return self._reject(index, "out_of_range", report, f"segment_{index}_is_not_a_known_gap")
            if current.status != STATUS_MISSING:
                if not os.path.isfile(self._journal.segment_path(index)):
                    return self._reject(
                        index, "manifest_orphan", report,
                        f"segment_{index}_manifest_exists_without_data",
                    )
                return self._reject(
                    index, self._classify_duplicate(index, records), report,
                    f"segment_{index}_already_present",
                )
            open_gaps_before = [gap for gap in report.missing if gap < index]
            if open_gaps_before:
                return self._reject(
                    index, "out_of_order", report,
                    f"fill_order_violation_wait_for_{open_gaps_before}",
                )
            anchors = self._anchors_before(index)
            predecessor = index - 1
            if predecessor >= 0 and self._load_manifest(predecessor) is None:
                return self._reject(
                    index, "anchor_unverifiable", report,
                    f"predecessor_segment_{predecessor}_not_trusted",
                )
            last_hash, _hashes = fold_records(records, anchors.record_anchor)
            computed_digest = segment_digest(anchors.segment_anchor, last_hash)
            successor = self._load_manifest(index + 1)
            if successor is not None:
                if str(successor.get("record_anchor", GENESIS)) != last_hash:
                    return self._reject(
                        index, "anchor_mismatch", self.verify(),
                        "backfill_records_do_not_chain_into_successor",
                        computed_digest=computed_digest,
                        expected_record_anchor=str(successor.get("record_anchor", "")),
                    )
                if str(successor.get("prev_digest", "")) != computed_digest:
                    return self._reject(
                        index, "anchor_mismatch", self.verify(),
                        "backfill_digest_does_not_match_successor_anchor",
                        computed_digest=computed_digest,
                        expected_digest=str(successor.get("prev_digest", "")),
                    )

            lock = self._backfill_locks.setdefault(index, threading.Lock())
            if not lock.acquire(blocking=False):
                return self._reject(
                    index, "duplicate_inflight", self.verify(),
                    f"segment_{index}_is_being_backfilled_concurrently",
                )
            try:
                if os.path.isfile(self._journal.segment_path(index)):
                    return self._reject(
                        index, self._classify_duplicate(index, records), self.verify(),
                        f"segment_{index}_appeared_during_backfill",
                    )
                self._journal.install_segment(index, records)
                manifest = self._build_manifest_payload(
                    index, records, anchors, origin="backfill", operator=operator
                )
                self._write_manifest(index, manifest)
                # 补的就是活动尾段：之后追加的记录要从这段末条记录哈希续下去，
                # 实时状态直接接在新清单后面；补的是更早的缺口则强制重新扎根。
                if index == self._journal.active_segment():
                    self._live = {
                        "version": CHAIN_VERSION,
                        "topic": self._topic,
                        "segment": index,
                        "count": len(records),
                        "prev_digest": anchors.segment_anchor,
                        "record_anchor": anchors.record_anchor,
                        "last_record_hash": manifest["last_record_hash"],
                        "digest": manifest["digest"],
                        "record_hashes": list(manifest["record_hashes"]),
                    }
                    self._write_live()
                else:
                    self._init_live_state(force_rebuild=True)
                refreshed = self.verify()
                return {
                    "ok": True,
                    "topic": self._topic,
                    "segment": index,
                    "decision": "proceed" if refreshed.proceed() else "abort",
                    "status": "filled",
                    "records_installed": len(records),
                    "anchor_digest": manifest["digest"],
                    "anchor_segment": predecessor,
                    "operator": operator,
                    "ts": round((now or time.time)(), 3),
                    "chain": refreshed.as_dict(),
                    "reason": "",
                }
            finally:
                lock.release()

    def _reject(self, index: int, status: str, report: ChainReport, reason: str, **extra) -> dict:
        outcome = {
            "ok": False,
            "topic": self._topic,
            "segment": index,
            "decision": "abort",
            "status": status,
            "records_installed": 0,
            "chain": report.as_dict(),
            "reason": reason,
        }
        outcome.update(extra)
        return outcome

    def _classify_duplicate(self, index: int, records: list[dict]) -> str:
        """对已存在的段判重复：内容一致是重复补，内容不同是与现状冲突。"""

        try:
            existing_records = self._journal.read_segment(index)
        except StorageError:
            return "duplicate_conflict"
        anchor = self._anchors_before(index)
        existing_tail, _ = fold_records(existing_records, anchor.record_anchor)
        incoming_tail, _ = fold_records(records, anchor.record_anchor)
        return "duplicate_applied" if existing_tail == incoming_tail else "duplicate_conflict"
