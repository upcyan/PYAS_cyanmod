"""ETW 能力探测:当前环境能否用 Microsoft-Windows-Kernel-File 追踪文件写入方。

本模块**只做能力判定**,不启动会话。原因:
真正消费 ETW 实时会话需要 StartTraceW/OpenTraceW/ProcessTrace 一整套,
现有依赖里没有可直接复用的消费者;
可选路线是 vendored `pywintrace` 或自研 C++ 助手,二者都需要单独评估许可与体积。

在消费者落地之前,`available()` 会如实返回「不可用 + 原因」,
上层据此回退到驱动事件与 Restart Manager,避免出现"开关打开了却什么都没发生"。
"""

from __future__ import annotations

import ctypes
import sys
from typing import Tuple

# Microsoft-Windows-Kernel-File provider GUID(需核实项:若未来升级到 v2 manifest 解析,
# 关键字位与事件 ID 需要按官方文档逐条对齐)
KERNEL_FILE_PROVIDER = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"


def is_elevated() -> bool:
    """当前进程是否具备管理员令牌。"""
    if sys.platform != "win32":
        return False

    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.IsUserAnAdmin.restype = ctypes.c_bool
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def consumer_module() -> str:
    """返回可用的 ETW 消费者模块名;没有则返回空串。"""
    try:
        import pywintrace  # noqa: F401

        return "pywintrace"
    except Exception:
        return ""


def available() -> Tuple[bool, str]:
    """(是否可用, 原因码)。

    原因码用于界面提示,例如 elevated-required / consumer-missing。
    """
    if sys.platform != "win32":
        return (False, "unsupported-platform")

    if not is_elevated():
        return (False, "elevated-required")

    if not consumer_module():
        # 需要管理员 + 消费者两者齐备;缺消费者时即便提权也用不了
        return (False, "consumer-missing")

    return (True, "ok")
