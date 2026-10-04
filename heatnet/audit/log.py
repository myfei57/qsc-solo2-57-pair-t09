"""审计日志。

``AuditLog`` 是事件总线的全量订阅者：组件只发布事件，日志把它们落成流水并保留
内存副本。控制台读内存副本，跨重启回放读落盘流水；两份数据都来自同一个
:class:`AuditRecord` 结构，字段口径一致。
"""

from __future__ import annotations

import threading

from ..clock import Clock
from ..eventbus import Event, EventBus
from ..store.chain import POLICY_MARK, POLICY_STRICT, ChainReport, SegmentChainGuard
from ..store.journal import JsonlJournal
from .record import AuditRecord
from .report import summarize


class AuditLog:
    """审计流水：内存副本 + 分段落盘。"""

    def __init__(
        self,
        clock: Clock,
        bus: EventBus,
        journal: JsonlJournal,
        memory_limit: int = 4096,
    ) -> None:
        self._clock = clock
        self._journal = journal
        self.chain = SegmentChainGuard(journal)
        self._entries: list[AuditRecord] = []
        self._memory_limit = max(1, memory_limit)
        self._lock = threading.RLock()
        bus.subscribe("*", self._on_event)

    @property
    def journal(self) -> JsonlJournal:
        return self._journal

    def _on_event(self, event: Event) -> None:
        severity = "notice"
        payload = dict(event.payload)
        if "severity" in payload:
            severity = str(payload.pop("severity"))
        asset = str(payload.pop("asset", ""))
        message = str(payload.pop("message", ""))
        # 事件载荷里可能出现与记录字段同名的键（例如采样自带的 ts），
        # 这些键只用于审计正文，不能覆盖记录本身的字段。
        for reserved in ("ts", "component", "action", "type"):
            payload.pop(reserved, None)
        self.record(
            AuditRecord.create(
                self._clock.now(), asset, event.component, event.action, severity, message, **payload
            )
        )

    def record(self, record: AuditRecord) -> dict:
        """记一条审计流水（内存 + 落盘），返回其字典形式。"""

        with self._lock:
            self._entries.append(record)
            if len(self._entries) > self._memory_limit:
                del self._entries[: len(self._entries) - self._memory_limit]
            self._journal.append(record.as_dict())
        return record.as_dict()

    def entries(self, limit: int = 100) -> list[dict]:
        """返回最近的记录（最新的在前）。"""

        with self._lock:
            selected = list(self._entries)[-limit:]
        return [entry.as_dict() for entry in reversed(selected)]

    def tail(self, limit: int = 20) -> list[dict]:
        """返回最近的记录（按时间升序）。"""

        with self._lock:
            selected = list(self._entries)[-limit:]
        return [entry.as_dict() for entry in selected]

    def alarms(self) -> list[dict]:
        """返回全部告警档记录。"""

        with self._lock:
            selected = [entry for entry in self._entries if entry.is_alarm()]
        return [entry.as_dict() for entry in selected]

    def records(self, limit: int = 200) -> list[AuditRecord]:
        """返回最近的记录对象（按时间升序），供时间线构造使用。"""

        with self._lock:
            return list(self._entries)[-limit:]

    def count(self, action: str) -> int:
        """统计某个动作累计出现过多少次。"""

        with self._lock:
            return len([entry for entry in self._entries if entry.action == action])

    def summary(self) -> dict:
        """返回审计汇总计数。"""

        with self._lock:
            entries = list(self._entries)
        report = summarize(entries)
        report["journal_count"] = self._journal.count()
        report["active_segment"] = self._journal.active_segment()
        return report

    def replay_from_journal(self, limit: int = 100_000) -> list[dict]:
        """标注读法回放落盘流水：好段原样返回，坏段记录带标记、缺段给占位。

        恢复用途需要整段拒读时走 :meth:`replay_verified` 的严格读法。
        """

        records, _report = self.chain.read_verified(POLICY_MARK, limit=limit)
        return records

    def replay_verified(
        self, policy: str = POLICY_STRICT, limit: int | None = None
    ) -> tuple[list[dict], ChainReport]:
        """按策略跨段校验后回放：``strict`` 整段拒读，``mark`` 标注后部分读。"""

        return self.chain.read_verified(policy, limit=limit)

    def chain_report(self) -> dict:
        """返回审计流水的跨段校验结论。"""

        return self.chain.verify().as_dict()

    def backfill_segment(
        self, index: int, records: list[dict], *, operator: str = "console"
    ) -> dict:
        """补齐审计流水的缺失段，顺序/锚点/重复由链校验器判死。"""

        return self.chain.backfill_segment(
            index, records, operator=operator, now=self._clock.now
        )

    def replay_segment(self, index: int) -> list[dict]:
        """按段号回放一段流水。"""

        return self._journal.read_segment(index)

    def to_records(self, raw: list[dict]) -> list[AuditRecord]:
        """把落盘字段还原成记录对象。"""

        return [AuditRecord.from_dict(item) for item in raw]
