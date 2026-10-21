"""文件发起进程溯源:分层缓存 + 统一查询入口。

为什么需要这一层
----------------
目录监听(ReadDirectoryChangesW)不携带发起方 PID,Restart Manager 只能看到
「此刻仍开着这个文件」的进程。对写完就关的文件(解包、编译产物、释放副本),
两条路都查不到,弹窗只能显示「未识别」。

分层顺序
--------
1. **驱动事件**(内核 minifilter):创建/写入时就能拿到 PsGetCurrentProcessId,
   最准,零额外系统开销;
2. **ETW**(Microsoft-Windows-Kernel-File):不需要驱动,覆盖全系统写入,
   代价是需要管理员权限 + 常驻消费者;
3. **Restart Manager**:调用方(PYAS_Dialog)在查不到时自行兜底。

本模块只负责 1、2 两层的缓存与查询,**不做**任何 OS 调用,
因此可以脱离驱动/ETW 单独测试。
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from typing import Optional, Tuple

# 缓存时长:事件发生后 20 秒内的扫描都能命中。
# 目录监听有 0.35s 防抖,扫描本身可能再等 0.35s,5~10 秒足够;给 20 秒留余量。
DRIVER_TTL_SECONDS = 20.0
ETW_TTL_SECONDS = 20.0

# 上限:避免长时间运行后无限增长(每条只是一个路径字符串 + 小元组)
MAX_ENTRIES = 512


class AttributionCache:
    """按路径缓存「谁写的」,带 TTL 与容量上限,线程安全。"""

    def __init__(self, ttl_seconds: float, max_entries: int = MAX_ENTRIES) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._lock = threading.Lock()
        self._entries: "OrderedDict[str, Tuple[int, str, float]]" = OrderedDict()

    @staticmethod
    def _key(path: str) -> str:
        return os.path.normcase(os.path.normpath(path))

    def record(self, path: str, pid: int, name: str = "", now: Optional[float] = None) -> None:
        if not path or not pid:
            return

        stamp = time.monotonic() if now is None else now
        key = self._key(path)

        with self._lock:
            self._entries[key] = (int(pid), name or "", stamp)
            self._entries.move_to_end(key)

            while len(self._entries) > self._max:
                self._entries.popitem(last=False)

    def lookup(
        self, path: str, now: Optional[float] = None
    ) -> Optional[Tuple[int, str]]:
        if not path:
            return None

        stamp = time.monotonic() if now is None else now
        key = self._key(path)

        with self._lock:
            entry = self._entries.get(key)

            if not entry:
                return None

            pid, name, recorded = entry

            if stamp - recorded > self._ttl:
                self._entries.pop(key, None)
                return None

            return (pid, name)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class AttributionLayer:
    """A(驱动) → B(ETW) 两级缓存;调用方拿不到时再退 Restart Manager。"""

    def __init__(self) -> None:
        self.driver = AttributionCache(DRIVER_TTL_SECONDS)
        self.etw = AttributionCache(ETW_TTL_SECONDS)
        self._stats = {"driver": 0, "etw": 0, "miss": 0}
        self._stats_lock = threading.Lock()

    def record_driver(self, path: str, pid: int, name: str = "") -> None:
        self.driver.record(path, pid, name)

    def record_etw(self, path: str, pid: int, name: str = "") -> None:
        self.etw.record(path, pid, name)

    def lookup(self, path: str) -> Optional[Tuple[int, str, str]]:
        """返回 (pid, 进程名, 来源),来源是 'driver' 或 'etw';都没有则 None。"""
        hit = self.driver.lookup(path)

        if hit:
            with self._stats_lock:
                self._stats["driver"] += 1

            return (hit[0], hit[1], "driver")

        hit = self.etw.lookup(path)

        if hit:
            with self._stats_lock:
                self._stats["etw"] += 1

            return (hit[0], hit[1], "etw")

        with self._stats_lock:
            self._stats["miss"] += 1

        return None

    def status(self) -> dict:
        with self._stats_lock:
            stats = dict(self._stats)

        return {
            "driver_entries": len(self.driver),
            "etw_entries": len(self.etw),
            "hits": stats,
        }


_LAYER: Optional[AttributionLayer] = None
_LAYER_LOCK = threading.Lock()


def get_layer() -> AttributionLayer:
    """进程内单例。"""
    global _LAYER

    if _LAYER is None:
        with _LAYER_LOCK:
            if _LAYER is None:
                _LAYER = AttributionLayer()

    return _LAYER
