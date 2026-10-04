"""文件型持久化。

``JsonStore`` 保存"当前态"文档（每个文档一个 JSON 文件，写时先落临时文件再原子
替换）；``JsonlJournal`` 保存"流水"（按分段追加，只追加不重写，段滚满时落封签
边车）；``chain`` 在封签上提供跨段校验、按策略读取与缺失段补齐；``StoreMetrics``
给出目录用量；``DurableState`` 与 ``CommandCheckpoint`` 是建立在文档存储之上的
两个语义封装，前者保存设备当前态，后者保存指令队列的已应用检查点。这些都落在
平台配置的 ``storage_root`` 下。
"""

from __future__ import annotations

from .chain import backfill_segments, digest_records, read_segment_verified, verify_journal
from .command import CommandCheckpoint
from .jsonfile import JsonStore
from .journal import JsonlJournal
from .metrics import StoreMetrics
from .state import DurableState

__all__ = [
    "CommandCheckpoint",
    "DurableState",
    "JsonStore",
    "JsonlJournal",
    "StoreMetrics",
    "backfill_segments",
    "digest_records",
    "read_segment_verified",
    "verify_journal",
]
