"""目录监视生命周期测试:真实内核 API,验证事件到达、停止自愈、句柄重开。"""
import os
import tempfile
import threading
import time
import unittest

from PYAS_Realtime import RealtimeMixin


class WatcherHarness(RealtimeMixin):
    """真实 protect_file_thread + 桩掉扫描/裁决重依赖,只验证事件管线。"""

    def __init__(self, watch_dir):
        self.lock_config = threading.RLock()
        self.lock_file_ops = threading.RLock()
        self.lock_workers = threading.RLock()
        self.feature_workers = {}
        self.feature_restarts = set()
        self.closing = False
        self.pyas_config = {
            "document_switch": True,
            "suffix_switch": True,
            "suffix": [".py", ".js", ".txt"],
        }
        self.kernel32 = __import__("ctypes").WinDLL("kernel32", use_last_error=True)
        self.path_user = watch_dir
        self.path_temp = os.path.join(watch_dir, "_mei_none")
        self.h_dir_file = None
        self.virus_lock = {}
        self.scanned = []

    def write_log(self, *args, **kwargs):
        pass

    def norm_path(self, path, must_exist=False):
        if not path:
            return ""
        path = os.path.normpath(path)
        if must_exist and not os.path.exists(path):
            return ""
        return path

    def is_in_whitelist(self, file_path):
        return False

    def safe_scan_engine(self, file_path):
        self.scanned.append(os.path.basename(file_path))
        return False

    def cloud_check(self, file_path):
        pass

    def lock_file(self, *args, **kwargs):
        pass

    def request_block_decision(self, *args, **kwargs):
        return False

    def manage_named_list(self, *args, **kwargs):
        return 0

    def calc_file_hash(self, file_path):
        return "0" * 64

    def _schedule_file_task(self, task_name, file_path, callback, delay=0):
        callback(file_path)
        return True

    def _schedule_recovery(self, reason):
        pass


class FileWatcherLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.harness = WatcherHarness(self.directory.name)
        self.thread = threading.Thread(target=self.harness.protect_file_thread, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not self.harness.h_dir_file:
            time.sleep(0.05)
        self.assertTrue(self.harness.h_dir_file, "watcher must arm a directory handle")
        self.addCleanup(self._stop)

    def _stop(self):
        self.harness.stop_dir_watcher()
        self.thread.join(3)
        self.assertFalse(self.thread.is_alive(), "watcher thread must exit after stop")

    def _wait_for(self, name, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if name in self.harness.scanned:
                return True
            time.sleep(0.05)
        return False

    def test_events_reach_scan_pipeline(self):
        probe = os.path.join(self.directory.name, "canary_event.py")
        with open(probe, "w") as f:
            f.write("x\n")
        self.assertTrue(self._wait_for("canary_event.py"))

    def test_arms_on_host_class_without_preset_attribute(self):
        # 回归测试:WindowAPI 宿主类不预置 h_dir_file,线程若直接引用会在
        # 首轮迭代 AttributeError → worker 无限重启(warning 刷屏)。
        # 用独立台架(不与 setUp 线程共享状态)保证确定性。
        class NakedHost(WatcherHarness):
            def __init__(self, watch_dir):
                super().__init__(watch_dir)
                del self.h_dir_file

        harness = NakedHost(self.directory.name)
        thread = threading.Thread(target=harness.protect_file_thread, daemon=True)
        thread.start()
        self.addCleanup(harness.stop_dir_watcher)
        self.addCleanup(thread.join, 3)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not getattr(harness, "h_dir_file", None):
            time.sleep(0.05)
        self.assertTrue(getattr(harness, "h_dir_file", None))
        self.assertTrue(thread.is_alive())
        probe = os.path.join(self.directory.name, "canary_nopreset.py")
        with open(probe, "w") as f:
            f.write("x\n")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and "canary_nopreset.py" not in harness.scanned:
            time.sleep(0.05)
        self.assertIn("canary_nopreset.py", harness.scanned)

    def test_stop_dir_watcher_wakes_pending_read_and_rearm_recovers(self):
        # 先确认读挂起中(无事件时线程阻塞在 ReadDirectoryChangesW)
        time.sleep(0.3)
        self.assertTrue(self.thread.is_alive())
        # 外部关闭 + 立即重开(模拟启动期句柄被收走的场景)
        self.harness.stop_dir_watcher()
        self.thread.join(3)
        self.assertFalse(self.thread.is_alive(), "pending read must abort, not hang forever")
        # 重新武装:guard 不应再被僵尸线程挡住
        harness2 = WatcherHarness(self.directory.name)
        thread2 = threading.Thread(target=harness2.protect_file_thread, daemon=True)
        thread2.start()
        self.addCleanup(harness2.stop_dir_watcher)
        self.addCleanup(thread2.join, 3)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not harness2.h_dir_file:
            time.sleep(0.05)
        self.assertTrue(harness2.h_dir_file)
        probe = os.path.join(self.directory.name, "canary_rearm.py")
        with open(probe, "w") as f:
            f.write("x\n")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and "canary_rearm.py" not in harness2.scanned:
            time.sleep(0.05)
        self.assertIn("canary_rearm.py", harness2.scanned)

    def test_stop_dir_watcher_is_safe_and_idempotent(self):
        # 外部裸 CloseHandle 的挂起无法在线程内自愈(读永不返回),这是把
        # 应用内所有关闭点统一改走 stop_dir_watcher(CancelIoEx)的原因;
        # 这里验证该助手本身:幂等、可安全处理失效句柄值。
        handle = self.harness.h_dir_file
        self.assertTrue(handle)
        self.harness.stop_dir_watcher()
        self.assertIsNone(self.harness.h_dir_file)
        self.harness.stop_dir_watcher()  # 无句柄:直接返回
        # 句柄值已失效:CloseHandle 返回 False 但不得抛异常
        self.harness.h_dir_file = handle
        self.harness.stop_dir_watcher()
        self.assertIsNone(self.harness.h_dir_file)


if __name__ == "__main__":
    unittest.main()
