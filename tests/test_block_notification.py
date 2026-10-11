"""拦截通知契约测试:BLOCK 日志不再自动弹 toast;仅自动拦截显式通知。"""
import threading
import unittest
from collections import deque
from unittest.mock import Mock

from PYAS_Dialog import DialogMixin
from PYAS_Logs import MAX_LOG_ENTRIES, LogMixin


class LogOwner(LogMixin):
    """真实 write_log/_append_log_entry + Mock 托盘,验证日志层不再触发通知。"""

    def __init__(self):
        self.tray_icon = Mock()
        self.lock_logs = threading.RLock()
        self.logs_data = deque(maxlen=MAX_LOG_ENTRIES)
        self.logs_dirty = False
        self._window = None


class NotificationOwner(DialogMixin):
    def __init__(self, **config):
        self.lock_config = threading.RLock()
        self.pyas_config = {"interactive_switch": False, **config}
        self.trigger_block_notification = Mock()
        self.get_block_action_title = Mock(return_value="File Protection")
        self._get_threat_queue = Mock(
            return_value=Mock(submit=Mock(return_value="block"))
        )


class LogNotificationTests(unittest.TestCase):
    def test_block_log_does_not_trigger_tray_toast(self):
        owner = LogOwner()
        owner.write_log("BLOCK", "File Block", source="C:\\x.exe")
        owner.tray_icon.notify.assert_not_called()

    def test_other_levels_untouched(self):
        owner = LogOwner()
        owner.write_log("INFO", "File Allow", source="C:\\x.exe")
        owner.tray_icon.notify.assert_not_called()


class DecisionNotificationTests(unittest.TestCase):
    def test_interactive_off_notifies_automatically(self):
        owner = NotificationOwner(interactive_switch=False)
        self.assertTrue(owner.request_block_decision("File Block", source="C:\\x.exe"))
        owner.trigger_block_notification.assert_called_once_with(
            "File Block", "C:\\x.exe", None, None
        )

    def test_interactive_popup_decision_does_not_notify(self):
        owner = NotificationOwner(interactive_switch=True)
        self.assertTrue(owner.request_block_decision("File Block", source="C:\\x.exe"))
        owner.trigger_block_notification.assert_not_called()
        owner._get_threat_queue.return_value.submit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
