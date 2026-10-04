"""分段 JSONL 流水日志。

流水只追加不重写，按 ``segment_limit`` 条一段滚动成 ``<topic>-00000.jsonl``、
``<topic>-00001.jsonl``…。审计回放需要按段读取，因此同时提供段号列表、单段读取
和全量读取三种入口。

段与段之间的密码学校验不由本类负责（见 :mod:`..store.chain`），但滚动一旦封段
会通知已登记的监听器，让链校验器在那一刻为封死的段生成清单；补段落盘走
:meth:`install_segment`，保证和正常滚动写出的字节口径一致。
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from typing import Any, Callable

from ..errors import StorageError

SegmentSealedListener = Callable[[str, int], None]
SegmentAppendListener = Callable[[str, int, dict], None]


class JsonlJournal:
    """按段落写入的 JSONL 流水。"""

    def __init__(self, root: str, topic: str, segment_limit: int = 512) -> None:
        self._root = os.path.abspath(root)
        self._topic = topic
        self._segment_limit = max(1, segment_limit)
        self._lock = threading.RLock()
        self._sealed_listeners: list[SegmentSealedListener] = []
        self._append_listeners: list[SegmentAppendListener] = []
        os.makedirs(self._root, exist_ok=True)
        self._count = self._existing_count()
        self._segment = self._highest_segment()

    @property
    def topic(self) -> str:
        return self._topic

    @property
    def root(self) -> str:
        return self._root

    @property
    def segment_limit(self) -> int:
        return self._segment_limit

    @property
    def lock(self) -> threading.RLock:
        """段级互斥锁；链校验、补段与并发追加共用同一把锁。"""

        return self._lock

    def add_sealed_listener(self, listener: SegmentSealedListener) -> None:
        """登记一个"段被封死"监听器，回调参数为 (topic, 被封段号)。"""

        self._sealed_listeners.append(listener)

    def add_append_listener(self, listener: SegmentAppendListener) -> None:
        """登记一个"记录已落盘"监听器，回调参数为 (topic, 段号, 记录)。"""

        self._append_listeners.append(listener)

    def segment_path(self, index: int) -> str:
        """返回某段号对应的数据文件路径（文件可能尚不存在）。"""

        return self._segment_path(index)

    def _segment_path(self, index: int) -> str:
        return os.path.join(self._root, f"{self._topic}-{index:05d}.jsonl")

    def _existing_count(self) -> int:
        # 逐段文件独立计数：中间某段被删（等待补段）时不能让活动段号被截断，
        # 否则缺段之后的所有段都会从流水视野里消失。
        pattern = re.compile(rf"^{re.escape(self._topic)}-(\d{{5}})\.jsonl$")
        total = 0
        try:
            names = os.listdir(self._root)
        except OSError:
            return 0
        for name in sorted(names):
            if not pattern.match(name):
                continue
            with open(os.path.join(self._root, name), "r", encoding="utf-8") as handle:
                total += sum(1 for line in handle if line.strip())
        return total

    def _highest_segment(self) -> int:
        pattern = re.compile(rf"^{re.escape(self._topic)}-(\d{{5}})\.jsonl$")
        highest = -1
        try:
            for name in os.listdir(self._root):
                match = pattern.match(name)
                if match:
                    highest = max(highest, int(match.group(1)))
        except OSError:
            return 0
        return max(0, highest)

    def _segment_fill(self, index: int) -> int:
        path = self._segment_path(index)
        if not os.path.isfile(path):
            return 0
        with open(path, "r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())

    def _next_append_segment(self) -> int:
        """决定下一条记录写哪段：活动段满就滚新段，缺段不影响活动段判定。

        段是否已满按该文件实际行数判，不能用总条数除段容量——中间缺段会让总
        条数与段号错位。
        """

        index = self._segment
        if (
            self._segment_fill(index) >= self._segment_limit
            and not os.path.isfile(self._segment_path(index + 1))
        ):
            return index + 1
        return index

    def append(self, record: Any) -> str:
        """追加一条记录，返回写入的段路径。"""

        with self._lock:
            index = self._next_append_segment()
            path = self._segment_path(index)
            try:
                with open(path, "a", encoding="utf-8") as handle:
                    line = json.dumps(record, ensure_ascii=False) + "\n"
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as error:
                raise StorageError(f"追加流水失败: {error}", component="store") from error
            self._count += 1
            sealed = self._segment
            self._segment = index
            # 监听器拿到的必须就是落盘字节解析回来的对象，否则哈希链锚的是
            # 内存对象而不是文件内容（例如调用方写盘前做了数值舍入）。
            payload = json.loads(line)
            if sealed < index:
                self._notify_sealed(sealed)
            self._notify_append(index, payload)
            return path

    def install_segment(self, index: int, records: list[dict]) -> str:
        """把补齐的缺失段原子落盘，返回段路径。

        只允许写当前不存在的段号；字节编码与 :meth:`append` 完全一致，补进来的
        段因此能和原生滚动段接受同一套跨段校验。调用方必须先完成顺序与锚点
        校验并持有:attr:`lock`。
        """

        path = self._segment_path(index)
        if os.path.exists(path):
            raise StorageError(f"段 {index} 已存在，禁止覆盖流水段", component="store")
        lines = [json.dumps(record, ensure_ascii=False) + "\n" for record in records]
        try:
            os.makedirs(self._root, exist_ok=True)
            handle = tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self._root,
                prefix=f".{self._topic}-{index:05d}.",
                suffix=".tmp",
                delete=False,
            )
            with handle:
                handle.writelines(lines)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, path)
        except OSError as error:
            raise StorageError(f"补齐流水段 {index} 失败: {error}", component="store") from error
        self._count = len(self.read_all())
        if index > self._segment:
            self._segment = self._highest_segment()
        return path

    def _notify_sealed(self, index: int) -> None:
        for listener in self._sealed_listeners:
            listener(self._topic, index)

    def _notify_append(self, index: int, record: dict) -> None:
        for listener in self._append_listeners:
            listener(self._topic, index, record)

    def segments(self) -> list[str]:
        """返回已存在的段文件路径（按段号升序）。"""

        found: list[str] = []
        for index in range(4096):
            path = self._segment_path(index)
            if not os.path.isfile(path):
                break
            found.append(path)
        return found

    def read_segment(self, index: int) -> list[dict]:
        """读取指定段。"""

        path = self._segment_path(index)
        if not os.path.isfile(path):
            return []
        return self._read_file(path)

    def read_all(self) -> list[dict]:
        """按段号顺序读取全部记录（不带跨段校验，链式读法见 chain 模块）。"""

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
