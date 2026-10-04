"""审计与趋势的同轴对齐回放。

审计记录与趋势采样本来是两条互不相干的序列，事后复盘要靠人对着看。这里把
两者合并到同一条时间轴——对齐口径定死为**同轴合并**，不做各轴独立：各轴
独立等于把对齐工作又推回给人。按固定槽宽分桶，每个槽带上落在里面的审计
记录与各信号的最新采样，槽按时间升序输出，控制台直接渲染这一条轴即可。
"""

from __future__ import annotations

import math

from ..telemetry import Sample
from .record import AuditRecord


def build_aligned_replay(
    records: list[AuditRecord], series: dict[str, list[Sample]], slot_s: float
) -> dict:
    """把审计与趋势合并到同一条时间轴，返回按槽升序的回放。"""

    if slot_s <= 0:
        raise ValueError("槽宽必须为正")
    slots: dict[int, dict] = {}
    audits = 0
    trend_points = 0
    first_ts: float | None = None
    last_ts: float | None = None

    def slot_for(ts: float) -> dict:
        key = math.floor(ts / slot_s)
        return slots.setdefault(
            key, {"slot": key, "ts": round(key * slot_s, 3), "audits": [], "trends": {}}
        )

    for record in sorted(records, key=lambda item: item.ts):
        slot_for(record.ts)["audits"].append(record.as_dict())
        audits += 1
        first_ts = record.ts if first_ts is None else min(first_ts, record.ts)
        last_ts = record.ts if last_ts is None else max(last_ts, record.ts)
    for signal in sorted(series):
        for sample in series[signal]:
            # 同一槽内同信号的多个采样只保留最新一个，槽网格保持齐整。
            slot_for(sample.ts)["trends"][signal] = sample.as_dict()
            trend_points += 1
            first_ts = sample.ts if first_ts is None else min(first_ts, sample.ts)
            last_ts = sample.ts if last_ts is None else max(last_ts, sample.ts)
    return {
        "axis": "merged",
        "slot_s": slot_s,
        "signals": sorted(series),
        "slots": [slots[key] for key in sorted(slots)],
        "audits": audits,
        "trend_points": trend_points,
        "span": None if first_ts is None else [round(first_ts, 3), round(last_ts, 3)],
    }
