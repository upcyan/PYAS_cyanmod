# -*- coding: utf-8 -*-
"""AMSI 脚本扫描通道(消费形态):借本机已注册的 AMSI provider(通常是
Windows Defender 的脚本引擎)对脚本类文件内容做启发式判定。

设计约束:
- **只做消费者**:PYAS 进程内调用 AmsiInitialize/AmsiScanBuffer,不注册
  COM provider、不影响系统其它组件;本机没有任何 provider 时 AmsiScan
  返回 NOT_DETECTED,自然回退到 PYAS 自己的 YARA 通道;
- **fail-open 到自有引擎**:AMSI 任何失败(无导出/初始化失败/异常)都
  返回 None,scan_engine 继续走 YARA —— 绝不因本通道异常漏扫;
- 命中判定按微软契约:result 为 AMSI_RESULT_DETECTED(0x8000)或
  BLOCKED_BY_ADMIN_STARTUP/SCAN(0x4000/0x4001)即恶意。

扫描的输入是文件内容(≤1MB,脚本文件罕见超限),名称传完整路径供
provider 上下文参考。
"""
import ctypes
import logging
import threading

logger = logging.getLogger("PYAS.AMSI")

AMSI_RESULT_DETECTED = 32768
AMSI_RESULT_BLOCKED_BY_ADMIN_STARTUP = 16384
AMSI_RESULT_BLOCKED_BY_ADMIN_SCAN = 16385

SCAN_LIMIT_BYTES = 1024 * 1024

# 内容判恶意:DETECTED 与两个 BLOCKED 态(0x4000/0x4001 与 0x8000)
def amsi_result_is_malware(result: int) -> bool:
    return result >= AMSI_RESULT_BLOCKED_BY_ADMIN_STARTUP


class AmsiScanner:
    """惰性初始化的进程内 AMSI 会话;线程安全。"""

    def __init__(self, app_name: str = "PYAS.Security.Cyanmod") -> None:
        self._lock = threading.Lock()
        self._context = None
        self._session = None
        self._failed = False
        self._app_name = app_name

    def _ensure(self) -> bool:
        if self._context is not None:
            return True

        if self._failed:
            return False

        with self._lock:
            if self._context is not None:
                return True

            if self._failed:
                return False

            try:
                amso = ctypes.windll.amsi
                self._context = ctypes.c_void_p()
                hr = amso.AmsiInitialize(self._app_name, ctypes.byref(self._context))

                if hr != 0 or not self._context:
                    self._failed = True
                    return False

                self._session = ctypes.c_void_p()
                hr = amso.AmsiOpenSession(self._context, ctypes.byref(self._session))

                if hr != 0 or not self._session:
                    self._failed = True
                    return False

                return True
            except Exception:
                logger.debug("AMSI init failed", exc_info=True)
                self._failed = True
                return False

    def scan_bytes(self, content: bytes, name: str):
        """返回 (is_malware, 判定值) 或 None(通道不可用/未判恶意由调用方
        继续自有管线;is_malware=False 表示已扫但无恶意结论)。"""
        if not content:
            return None

        if not self._ensure():
            return None

        try:
            amso = ctypes.windll.amsi
            result = ctypes.c_int(0)
            buffer = ctypes.create_string_buffer(content, len(content))
            hr = amso.AmsiScanBuffer(
                self._context, buffer, ctypes.c_ulong(len(content)),
                name, self._session, ctypes.byref(result),
            )

            if hr != 0:
                return None

            malware = amsi_result_is_malware(result.value)
            return (malware, result.value)
        except Exception:
            logger.debug("AMSI scan failed", exc_info=True)
            return None

    def scan_file(self, file_path: str):
        """读文件内容并扫描;返回 (True, 判定值) / (False, 判定值) / None。"""
        try:
            with open(file_path, "rb") as handle:
                content = handle.read(SCAN_LIMIT_BYTES)

            return self.scan_bytes(content, file_path)
        except OSError:
            return None


_scanner = None
_scanner_lock = threading.Lock()


def get_scanner() -> AmsiScanner:
    global _scanner

    with _scanner_lock:
        if _scanner is None:
            _scanner = AmsiScanner()

        return _scanner
