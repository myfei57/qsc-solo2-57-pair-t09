"""文件型持久化。

``JsonStore`` 保存"当前态"文档（每个文档一个 JSON 文件，写时先落临时文件再原子
替换）；``JsonlJournal`` 保存"流水"（按分段追加，只追加不重写）；
``SegmentChainGuard`` 给分段流水套记录级＋段级哈希链，负责跨段校验、带策略读法
与补段；``StoreMetrics`` 给出目录用量；``DurableState`` 与
``CommandCheckpoint`` 是建立在文档存储之上的两个语义封装，前者保存设备当前态，
后者保存指令队列的已应用检查点。六者都落在平台配置的 ``storage_root`` 下。
"""

from __future__ import annotations

from .chain import (
    POLICY_MARK,
    POLICY_STRICT,
    ChainReport,
    SegmentChainGuard,
)
from .command import CommandCheckpoint
from .jsonfile import JsonStore
from .journal import JsonlJournal
from .metrics import StoreMetrics
from .state import DurableState

__all__ = [
    "ChainReport",
    "CommandCheckpoint",
    "DurableState",
    "JsonStore",
    "JsonlJournal",
    "POLICY_MARK",
    "POLICY_STRICT",
    "SegmentChainGuard",
    "StoreMetrics",
]
