"""审计与趋势按同一条时间轴对齐回放。

审计流水在分段落盘文件里，趋势采样原本只在内存，两边对时间全靠人眼。本模块
把"对齐方式"定死为**同轴合并**：审计记录与趋势点都投影到同一条时间轴上按
``(ts, 轴序)`` 稳定排序，同一时刻审计在前、趋势在后；不存在"各轴独立"的第二
种口径，控制台展示、落盘审计与跨重启复盘拿到的是同一份有序结果。

趋势轴在投影前先按固定周期线性补齐丢点周期（补出来的点带 ``filled: true``）；
标注读法下检出的缺段没有时间戳，按"该段之后同一条轴上第一个有效点之前"的
位置插进时间轴，轴上后面再没有有效点时贴队尾，缺口因此紧跟在它该在的位置。
"""

from __future__ import annotations

from ..store.chain import (
    CHAIN_REASON_KEY,
    CHAIN_SEGMENT_KEY,
    CHAIN_STATUS_KEY,
    POLICY_MARK,
    POLICY_STRICT,
    ChainReport,
    STATUS_OK,
)
from .record import AuditRecord

ALIGNMENT_COAXIS = "coaxis_merge"

AXIS_AUDIT = "audit"
AXIS_TREND = "trend"

_SEGMENT_KEY = "_source_segment"


def fill_series(ts_values: list[tuple[float, float]], period_s: float) -> list[dict]:
    """对一条信号的 (ts, value) 序列按固定周期线性补点。"""

    ordered = sorted(ts_values, key=lambda item: item[0])
    if len(ordered) < 2:
        return [
            {"ts": round(ts, 3), "value": round(value, 4), "filled": False}
            for ts, value in ordered
        ]
    points: list[dict] = [
        {"ts": round(ordered[0][0], 3), "value": round(ordered[0][1], 4), "filled": False}
    ]
    for previous, current in zip(ordered, ordered[1:]):
        steps = int(round((current[0] - previous[0]) / period_s))
        if steps > 1:
            for index in range(1, steps):
                ratio = index / steps
                points.append(
                    {
                        "ts": round(previous[0] + (current[0] - previous[0]) * ratio, 3),
                        "value": round(
                            previous[1] + (current[1] - previous[1]) * ratio, 4
                        ),
                        "filled": True,
                    }
                )
        points.append(
            {"ts": round(current[0], 3), "value": round(current[1], 4), "filled": False}
        )
    return points


def _split_marked(records: list[dict]) -> tuple[list[dict], list[dict]]:
    clean: list[dict] = []
    placeholders: list[dict] = []
    for item in records:
        if item.get(CHAIN_STATUS_KEY) == "missing":
            placeholders.append(item)
        else:
            clean.append(item)
    return clean, placeholders


def _audit_entry(raw: dict) -> dict:
    status = raw.get(CHAIN_STATUS_KEY, STATUS_OK)
    entry: dict = {
        "ts": float(raw.get("ts", 0.0)),
        "axis": AXIS_AUDIT,
        "kind": "audit",
        "asset": raw.get("asset", ""),
        "component": raw.get("component", ""),
        "action": raw.get("action", ""),
        "severity": raw.get("severity", "notice"),
        "message": raw.get("message", ""),
        "payload": raw.get("payload", {}),
        _SEGMENT_KEY: raw.get(CHAIN_SEGMENT_KEY),
    }
    if status != STATUS_OK:
        entry["status"] = status
        entry["reason"] = raw.get(CHAIN_REASON_KEY, "")
        entry["segment"] = raw.get(CHAIN_SEGMENT_KEY)
    return entry


def _gap_marker(raw: dict, axis: str) -> dict:
    return {
        "ts": None,
        "axis": axis,
        "kind": "gap",
        "segment": raw.get(CHAIN_SEGMENT_KEY),
        "status": "missing",
        "reason": raw.get(CHAIN_REASON_KEY, ""),
    }


def _interleave_gaps(ordered: list[dict], gaps_by_axis: dict[str, list[dict]]) -> list[dict]:
    """把缺段占位插到同轴该段之后第一个有效点之前。"""

    timeline: list[dict] = []
    remaining = {
        axis: sorted(markers, key=lambda marker: marker["segment"])
        for axis, markers in gaps_by_axis.items()
    }

    def drain_due(axis: str, segment: int | None) -> None:
        if segment is None:
            return
        due = [marker for marker in remaining[axis] if marker["segment"] <= segment]
        for marker in due:
            remaining[axis].remove(marker)
            timeline.append({"step": len(timeline) + 1, **marker})

    for entry in ordered:
        axis = entry["axis"]
        drain_due(axis, entry.get(_SEGMENT_KEY))
        segment = entry.pop(_SEGMENT_KEY, None)
        if isinstance(segment, int):
            entry["segment"] = segment
        timeline.append({"step": len(timeline) + 1, **entry})
    for axis in (AXIS_AUDIT, AXIS_TREND):
        for marker in remaining[axis]:
            timeline.append({"step": len(timeline) + 1, **marker})
    return timeline


def build_aligned_replay(
    audit_records: list[dict],
    trend_records: list[dict],
    *,
    period_s: float = 5.0,
    limit_per_axis: int = 5000,
    audit_chain: ChainReport | None = None,
    trend_chain: ChainReport | None = None,
    policy: str = POLICY_MARK,
) -> dict:
    """把审计与趋势同轴合并成一条带序号的时间轴。"""

    if policy not in (POLICY_MARK, POLICY_STRICT):
        raise ValueError(f"未知的链读法: {policy}")

    audit_clean, audit_gaps_raw = _split_marked(audit_records[-limit_per_axis:])
    trend_clean, trend_gaps_raw = _split_marked(trend_records[-limit_per_axis:])

    ordered: list[dict] = [_audit_entry(raw) for raw in audit_clean]

    grouped: dict[str, list[tuple[float, float]]] = {}
    trend_flags: dict[tuple[str, float], dict] = {}
    trend_segments: dict[tuple[str, float], int] = {}
    for raw in trend_clean:
        signal = str(raw.get("signal", ""))
        ts = float(raw.get("ts", 0.0))
        value = float(raw.get("value", 0.0))
        grouped.setdefault(signal, []).append((ts, value))
        if raw.get(CHAIN_STATUS_KEY, STATUS_OK) != STATUS_OK:
            trend_flags[(signal, ts)] = {
                "status": raw[CHAIN_STATUS_KEY],
                "reason": raw.get(CHAIN_REASON_KEY, ""),
            }
        if raw.get(CHAIN_SEGMENT_KEY) is not None:
            trend_segments[(signal, ts)] = raw[CHAIN_SEGMENT_KEY]

    trend_points: dict[str, list[dict]] = {}
    trend_tick_count = 0
    filled_count = 0
    for signal, values in sorted(grouped.items()):
        points = fill_series(values, period_s)
        trend_points[signal] = points
        trend_tick_count += len(points)
        filled_count += sum(1 for point in points if point["filled"])
        ticks: dict[float, list[dict]] = {}
        for point in points:
            ticks.setdefault(float(point["ts"]), []).append({"signal": signal, **point})
        for ts, samples in ticks.items():
            entry: dict = {
                "ts": ts,
                "axis": AXIS_TREND,
                "kind": "trend",
                "samples": samples,
                _SEGMENT_KEY: trend_segments.get((signal, ts)),
            }
            flag = trend_flags.get((signal, ts))
            if flag is not None:
                entry["status"] = flag["status"]
                entry["reason"] = flag["reason"]
                entry["segment"] = trend_segments.get((signal, ts))
            ordered.append(entry)

    ordered.sort(key=lambda item: (item["ts"], 0 if item["axis"] == AXIS_AUDIT else 1))
    timeline = _interleave_gaps(
        ordered,
        {
            AXIS_AUDIT: [_gap_marker(raw, AXIS_AUDIT) for raw in audit_gaps_raw],
            AXIS_TREND: [_gap_marker(raw, AXIS_TREND) for raw in trend_gaps_raw],
        },
    )

    audit_chain_dict = audit_chain.as_dict() if audit_chain is not None else None
    trend_chain_dict = trend_chain.as_dict() if trend_chain is not None else None
    chains_ok = all(chain is None or chain.ok() for chain in (audit_chain, trend_chain))
    return {
        "alignment": ALIGNMENT_COAXIS,
        "policy": policy,
        "period_s": period_s,
        "timeline": timeline,
        "tracks": {"audit": audit_chain_dict, "trend": trend_chain_dict},
        "coverage": {
            "audit_records": len(audit_clean),
            "audit_gaps": len(audit_gaps_raw),
            "trend_signals": len(trend_points),
            "trend_ticks": trend_tick_count,
            "trend_filled": filled_count,
            "trend_gaps": len(trend_gaps_raw),
        },
        "ok": chains_ok,
        "decision": "proceed" if chains_ok else "abort",
    }


def parse_audit(records: list[dict]) -> list[AuditRecord]:
    """把同轴回放用的审计字段还原成记录对象（缺段占位除外）。"""

    return [
        AuditRecord.from_dict(item)
        for item in records
        if item.get(CHAIN_STATUS_KEY) != "missing"
    ]
