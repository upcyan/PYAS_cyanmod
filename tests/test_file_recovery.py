"""文件事件恢复:触发原因分级 + 调度合并/冷却。全部离线,不碰真实文件系统。"""
import threading
import time
import unittest

from PYAS_Realtime import RECOVERY_MIN_INTERVAL, RECOVERY_REASONS, RealtimeMixin


class StubOwner:
    """只提供 _recover_file_tasks / _schedule_recovery 用到的属性。"""

    def __init__(self):
        self.lock_file_ops = threading.RLock()
        self.lock_config = threading.RLock()
        self.pyas_config = {
            "quarantine": [],
            "document_switch": True,
            "suffix_switch": True,
            "suffix": [],
        }
        self.closing = False
        self.path_user = r"C:\Users\stub"
        self.path_temp = r"C:\Users\stub\AppData\Local\Temp"
        self.logs = []
        self.handled = []

    def write_log(self, level, action, detail=None, success=True, **kwargs):
        self.logs.append((level, action, detail))

    def lock_file(self, *args, **kwargs):
        pass

    def yield_files(self, path):
        return iter(())

    def is_in_whitelist(self, path):
        return False

    def handle_new_file(self, path):
        self.handled.append(path)


class ReasonLevelTests(unittest.TestCase):
    def test_reason_to_level_mapping(self):
        # 队列慢没丢事件 → INFO;OS 丢事件 / 读失败 → WARN
        self.assertEqual(RECOVERY_REASONS["queue_full"][0], "INFO")
        self.assertEqual(RECOVERY_REASONS["buffer_lost"][0], "WARN")
        self.assertEqual(RECOVERY_REASONS["watcher_error"][0], "WARN")

    def test_recover_logs_reason_and_level(self):
        for reason in ("queue_full", "buffer_lost", "watcher_error"):
            owner = StubOwner()
            RealtimeMixin._recover_file_tasks(owner, reason)
            level, action, detail = owner.logs[0]
            self.assertEqual(action, "File Event Recovery")
            self.assertEqual(level, RECOVERY_REASONS[reason][0], reason)
            self.assertEqual(detail, RECOVERY_REASONS[reason][1])

    def test_unknown_reason_falls_back_to_queue_full(self):
        owner = StubOwner()
        RealtimeMixin._recover_file_tasks(owner, "something_else")
        self.assertEqual(owner.logs[0][2], RECOVERY_REASONS["queue_full"][1])


class ScheduleCooldownTests(unittest.TestCase):
    def _owner(self):
        owner = StubOwner()
        owner.scheduled = []

        def fake_schedule(task_name, path, callback, delay, **kwargs):
            owner.scheduled.append((task_name, delay, callback))
            return True

        owner._schedule_file_task = fake_schedule
        return owner

    def test_first_schedule_is_immediate(self):
        owner = self._owner()
        self.assertTrue(RealtimeMixin._schedule_recovery(owner, "buffer_lost"))
        self.assertEqual(owner.scheduled[0][0], "recovery")
        self.assertEqual(owner.scheduled[0][1], 0.0)

    def test_second_schedule_while_pending_is_skipped(self):
        owner = self._owner()
        RealtimeMixin._schedule_recovery(owner, "queue_full")
        # 已排队:再次触发不得重置到期时间(否则高频触发会把恢复永久推后)
        self.assertFalse(RealtimeMixin._schedule_recovery(owner, "buffer_lost"))
        self.assertEqual(len(owner.scheduled), 1)

    def test_after_run_respects_min_interval(self):
        owner = self._owner()
        RealtimeMixin._schedule_recovery(owner, "queue_full")
        RealtimeMixin._recover_file_tasks(owner, "queue_full")
        self.assertFalse(getattr(owner, "_recovery_scheduled", True), "跑完后必须清标记")
        owner.scheduled.clear()
        RealtimeMixin._schedule_recovery(owner, "queue_full")
        delay = owner.scheduled[0][1]
        self.assertGreater(delay, RECOVERY_MIN_INTERVAL - 5)
        self.assertLessEqual(delay, RECOVERY_MIN_INTERVAL)

    def test_failed_schedule_clears_flag(self):
        owner = self._owner()
        owner._schedule_file_task = lambda *args, **kwargs: False
        self.assertFalse(RealtimeMixin._schedule_recovery(owner, "queue_full"))
        self.assertFalse(getattr(owner, "_recovery_scheduled", False), "调度失败要清标记,否则永久卡住")


if __name__ == "__main__":
    unittest.main()
