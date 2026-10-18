"""日志落盘失败可见性测试:flush 失败必须在界面日志页可见,恢复时也告知。

背景(2026-10-16 ACL 事故):Report.json 被提权进程以 Administrators 所有写入后,
普通身份运行的应用 os.replace 永久 PermissionError,所有日志静默积压在内存里,
界面上毫无征兆——因为失败经 log_exception 走 Exception 通道,默认不进日志页。
flush_logs_now 现在在状态翻转时写一条 ui_visible=True 的可见条目。
"""
import threading
import unittest
from collections import deque
from unittest.mock import patch

from PYAS_Diagnostics import MAX_LOG_ENTRIES, is_ui_log_entry
# This test never opens a desktop/file dialog; use an explicit optional-UI stub
# when running its pure log state machine without pywebview installed.
import sys
from types import ModuleType
try:
    import webview
except ImportError:
    sys.modules.setdefault('webview', ModuleType('webview'))
from PYAS_Logs import LogMixin


class LogOwner(LogMixin):
    def __init__(self):
        self.lock_logs = threading.RLock()
        self.logs_data = deque(maxlen=MAX_LOG_ENTRIES)
        self.logs_dirty = False
        self._window = None
        self.file_log = r"C:\ProgramData\PYAS\Report.json"
        self._flush_failing = False


class FlushVisibilityTests(unittest.TestCase):
    def _visible_warnings(self, owner):
        return [
            e for e in owner.logs_data
            if e["action"] == "Log Write Failed" and is_ui_log_entry(e)
        ]

    def test_failure_writes_one_visible_warning(self):
        owner = LogOwner()
        owner.write_log("INFO", "Agent Detected", source="x.exe")

        with patch("PYAS_Logs.atomic_write_json",
                   side_effect=PermissionError(5, "拒绝访问。")):
            self.assertFalse(owner.flush_logs_now())
            self.assertFalse(owner.flush_logs_now())  # 持续失败不重复报

        visible = self._visible_warnings(owner)
        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0]["level"], "WARN")
        self.assertTrue(visible[0].get("ui_visible"))
        self.assertIn("拒绝访问", visible[0]["detail"])
        # dirty 保持 True:修复权限后下一轮 flush 能把积压全部带出去
        self.assertTrue(owner.logs_dirty)

    def test_recovery_writes_info_once(self):
        owner = LogOwner()
        # 先失败一次,再成功一次:全程 mock,绝不触碰真实的 Report.json
        with patch("PYAS_Logs.atomic_write_json",
                   side_effect=[PermissionError(5, "拒绝访问。"), None]):
            owner.write_log("INFO", "Agent Detected", source="x.exe")
            self.assertFalse(owner.flush_logs_now())

            owner.write_log("INFO", "Agent Detected", source="y.exe")
            self.assertTrue(owner.flush_logs_now())

        visible = self._visible_warnings(owner)
        self.assertEqual(len(visible), 2)  # 失败一条 + 恢复一条
        self.assertEqual(visible[-1]["level"], "INFO")
        self.assertIn("恢复", visible[-1]["detail"])
        self.assertFalse(owner._flush_failing)

    def test_healthy_flush_stays_silent(self):
        owner = LogOwner()
        with patch("PYAS_Logs.atomic_write_json") as mock_write:
            owner.write_log("INFO", "File Block", source="x.exe")
            self.assertTrue(owner.flush_logs_now())
            mock_write.assert_called_once_with(owner.file_log, owner.logs_data)
        self.assertEqual(self._visible_warnings(owner), [])
        self.assertFalse(owner.logs_dirty)


if __name__ == "__main__":
    unittest.main()
