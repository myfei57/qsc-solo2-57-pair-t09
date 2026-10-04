"""分段 JSONL 流水日志。

流水只追加不重写，按 ``segment_limit`` 条一段滚动成 ``<topic>-00000.jsonl``、
``<topic>-00001.jsonl``…。每段滚满时落一个封签边车文件（段号、条数、内容摘要、
前段摘要），段与段咬合成链，缺段或被改都能在校验时定位到段号；活动段还在写，
不封不验。打开时按磁盘现状恢复计数，已完整却没封签的段会补封（前序段缺失、
无法成链的保持未封，留给校验报告点名）。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Any

from ..errors import StorageError
from .chain import GENESIS_HASH, digest_records


class JsonlJournal:
    """按段落写入、滚满封签的 JSONL 流水。"""

    def __init__(self, root: str, topic: str, segment_limit: int = 512) -> None:
        self._root = os.path.abspath(root)
        self._topic = topic
        self._segment_limit = max(1, segment_limit)
        self._lock = threading.RLock()
        self._sizes: dict[int, int] = {}
        self._count = 0
        self._segment = 0
        os.makedirs(self._root, exist_ok=True)
        self.rescan()
        self.seal_complete_segments()

    @property
    def topic(self) -> str:
        return self._topic

    @property
    def segment_limit(self) -> int:
        return self._segment_limit

    def segment_path(self, index: int) -> str:
        """返回某一段的落盘路径。"""

        return os.path.join(self._root, f"{self._topic}-{index:05d}.jsonl")

    def _seal_path(self, index: int) -> str:
        return os.path.join(self._root, f"{self._topic}-{index:05d}.seal.json")

    def segment_indices(self) -> list[int]:
        """返回磁盘上实际存在的段号（含缺口），升序。"""

        prefix = f"{self._topic}-"
        found: list[int] = []
        for name in os.listdir(self._root):
            if not name.startswith(prefix) or not name.endswith(".jsonl"):
                continue
            try:
                found.append(int(name[len(prefix) : -len(".jsonl")]))
            except ValueError:
                continue
        return sorted(found)

    def rescan(self) -> None:
        """按磁盘现状重算各段条数、总条数与活动段（外部补齐段落后调用）。"""

        with self._lock:
            sizes: dict[int, int] = {}
            for index in self.segment_indices():
                with open(self.segment_path(index), "r", encoding="utf-8") as handle:
                    sizes[index] = sum(1 for line in handle if line.strip())
            self._sizes = sizes
            self._count = sum(sizes.values())
            self._segment = max(sizes) if sizes else 0

    def seal(self, index: int) -> dict | None:
        """读取某段的封签，不存在时返回 ``None``。"""

        path = self._seal_path(index)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            raise StorageError(f"读取封签 {path} 失败: {error}", component="store") from error

    def seal_segment(self, index: int) -> dict | None:
        """为已完整的段补写封签；前序段封签缺失时无法成链，返回 ``None`` 保持未封。"""

        with self._lock:
            if not os.path.isfile(self.segment_path(index)):
                return None
            if index == 0:
                prev_hash = GENESIS_HASH
            else:
                previous = self.seal(index - 1)
                if previous is None:
                    return None
                prev_hash = previous.get("hash")
            records = self.read_segment(index)
            seal = {
                "index": index,
                "count": len(records),
                "hash": digest_records(records),
                "prev_hash": prev_hash,
            }
            self._write_seal(index, seal)
            return seal

    def seal_complete_segments(self) -> list[int]:
        """给所有已完整但未封签的段补封签（前序缺失的保持未封），返回新封的段号。"""

        sealed: list[int] = []
        with self._lock:
            for index in sorted(self._sizes):
                if index >= self._segment or self.seal(index) is not None:
                    continue
                if self.seal_segment(index) is not None:
                    sealed.append(index)
        return sealed

    def _write_seal(self, index: int, seal: dict) -> None:
        target = self._seal_path(index)
        handle = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=self._root, prefix=".seal.", suffix=".tmp", delete=False
        )
        try:
            with handle:
                json.dump(seal, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, target)
        except OSError as error:
            raise StorageError(f"写入封签 {target} 失败: {error}", component="store") from error

    def append(self, record: Any) -> str:
        """追加一条记录，返回写入的段路径。"""

        with self._lock:
            if self._sizes.get(self._segment, 0) >= self._segment_limit:
                # 刚滚满的段落封签后再开新段，封签随段走、只增不改。
                self.seal_segment(self._segment)
                self._segment += 1
            path = self.segment_path(self._segment)
            try:
                with open(path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as error:
                raise StorageError(f"追加流水失败: {error}", component="store") from error
            self._sizes[self._segment] = self._sizes.get(self._segment, 0) + 1
            self._count += 1
            return path

    def segments(self) -> list[str]:
        """返回从首段起连续存在的段文件路径（按段号升序，遇缺口即止）。"""

        found: list[str] = []
        for index in range(4096):
            path = self.segment_path(index)
            if not os.path.isfile(path):
                break
            found.append(path)
        return found

    def read_segment(self, index: int) -> list[dict]:
        """读取指定段。"""

        path = self.segment_path(index)
        if not os.path.isfile(path):
            return []
        return self._read_file(path)

    def read_all(self) -> list[dict]:
        """按段号顺序读取全部记录。"""

        records: list[dict] = []
        for path in self.segments():
            records.extend(self._read_file(path))
        return records

    def count(self) -> int:
        """返回累计写入条数。"""

        with self._lock:
            return self._count

    def active_segment(self) -> int:
        """返回当前正在写入的段号。"""

        with self._lock:
            return self._segment

    def _read_file(self, path: str) -> list[dict]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return [json.loads(line) for line in handle if line.strip()]
        except (OSError, json.JSONDecodeError) as error:
            raise StorageError(f"读取流水 {path} 失败: {error}", component="store") from error
