"""文件占用进程反查测试:文件防护告警的「操作发起方」数据源。

正例用子进程真实持有文件句柄验证;同时验证自身句柄被排除、不存在文件快速降级、
看门狗超时存在(不会永久卡死扫描线程),以及端到端:request_block_decision 的消息体
带上反查到的发起方进程。
"""
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock

from PYAS_Dialog import DialogMixin, _RM_QUERY_TIMEOUT, _query_file_users


class FileOwnerTests(unittest.TestCase):
    def test_missing_file_degrades_fast(self):
        started = time.monotonic()
        self.assertEqual(_query_file_users("C:\\__pyas_no_such_file__.bin"), [])
        self.assertLess(time.monotonic() - started, _RM_QUERY_TIMEOUT + 1.0)

    def test_empty_path(self):
        self.assertEqual(_query_file_users(""), [])
        self.assertEqual(_query_file_users(None), [])

    def test_own_handle_is_excluded(self):
        fd, path = tempfile.mkstemp(suffix=".bin")
        try:
            with os.fdopen(fd, "rb") as handle:
                users = _query_file_users(path)
                self.assertTrue(all(pid != os.getpid() for pid, _ in users),
                    "PYAS 自持的扫描闸门句柄不得被当成发起方")
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_writer_process_is_found(self):
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        # venv 的 python.exe 是重定向器:真正执行 -c 的是基解释器进程,须按基路径起子进程
        child = subprocess.Popen(
            [sys._base_executable, "-c", f"import time; f=open({path!r},'rb'); time.sleep(8)"]
        )
        try:
            time.sleep(1.0)  # 等待子进程解释器启动并打开文件
            users = _query_file_users(path)
            pids = [pid for pid, _ in users]
            self.assertIn(child.pid, pids, f"应反查到写入门进程,实际: {users}")
            self.assertNotIn(os.getpid(), pids)
            name = next(name for pid, name in users if pid == child.pid)
            self.assertTrue(name, "RM 应同时给出进程名")
        finally:
            child.terminate()
            child.wait(timeout=5)
            for _ in range(10):
                try:
                    os.unlink(path)
                    break
                except PermissionError:
                    time.sleep(0.1)

    def test_closed_file_degrades_to_empty(self):
        # 写后即关:扫描时已无占用,返回空属正常降级(与改造前表现一致)
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        try:
            self.assertEqual(_query_file_users(path), [])
        finally:
            os.unlink(path)


class _DecisionOwner(DialogMixin):
    """最小决策 owner:捕获提交的 _DecisionRequest,get_exe_info 记录被查询的 PID。"""

    def __init__(self):
        self.lock_config = threading.RLock()
        self.pyas_config = {"interactive_switch": True, "language": "simplified_switch"}
        self.submitted = []
        self.exe_lookups = []

    def get_exe_info(self, pid):
        self.exe_lookups.append(pid)
        return "writer.exe", "C:\\demo\\writer.exe"

    def get_block_action_title(self, action):
        return action

    def _get_threat_queue(self):
        queue = Mock()
        queue.submit = Mock(side_effect=lambda request: self.submitted.append(request) or "block")
        return queue


class FileBlockDecisionTests(unittest.TestCase):
    def test_file_block_message_carries_resolved_process(self):
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        child = subprocess.Popen(
            [sys._base_executable, "-c", f"import time; f=open({path!r},'rb'); time.sleep(8)"]
        )
        owner = _DecisionOwner()
        try:
            time.sleep(1.0)
            owner.request_block_decision("File Block", source=path, detection={"name": "EICAR"})
            self.assertEqual(len(owner.submitted), 1)
            request = owner.submitted[0]
            self.assertIn(child.pid, owner.exe_lookups, "应先用反查 PID 解析进程信息")
            self.assertEqual(request.process_name, "writer.exe")
            self.assertEqual(request.process_path, "C:\\demo\\writer.exe")
            self.assertIn("进程: writer.exe", request.message)
        finally:
            child.terminate()
            child.wait(timeout=5)
            for _ in range(10):
                try:
                    os.unlink(path)
                    break
                except PermissionError:
                    time.sleep(0.1)

    def test_file_block_without_holder_has_no_process_line(self):
        owner = _DecisionOwner()
        owner.request_block_decision("File Block", source="C:\\__pyas_no_such_file__.bin")
        self.assertEqual(len(owner.submitted), 1)
        self.assertEqual(owner.submitted[0].process_name, "")
        self.assertNotIn("Process:", owner.submitted[0].message)
        self.assertEqual(owner.exe_lookups, [], "无占用时不应触发进程解析")

    def test_process_block_keeps_pid_path(self):
        # 带 PID 的进程类告警走原路径,不触发 RM 反查
        owner = _DecisionOwner()
        owner.request_block_decision("Process Block", source="C:\\demo\\a.exe", pid=4242)
        self.assertEqual(owner.exe_lookups, [4242])
        self.assertEqual(owner.submitted[0].process_name, "writer.exe")


if __name__ == "__main__":
    unittest.main()


class EarlyOwnerSnapshotTests(unittest.TestCase):
    """目录监听侧在事件刚到时抄下发起方,弹窗优先用它。

    背景:扫描要等 0.35s 防抖,写后即关的文件到弹窗时已无占用,
    Restart Manager 只能返回空 —— 表现为「进程:未识别」。
    """

    def _owner(self):
        from PYAS_Realtime import RealtimeMixin

        class Owner(RealtimeMixin):
            pass

        return Owner()

    def test_cached_pid_is_returned_within_ttl(self):
        from PYAS_Realtime import FILE_OWNER_TTL_SECONDS

        owner = self._owner()
        owner._file_owner_state()
        path = r"C://demo//pull-requests.js"

        with owner._file_owner_lock:
            owner._file_owner_cache[os.path.normcase(path)] = (4321, "node.exe", time.monotonic())

        self.assertEqual(owner._file_owner_for(path), (4321, "node.exe"))
        self.assertEqual(owner._file_owner_for(path.upper()), (4321, "node.exe"), "路径大小写不敏感")

        with owner._file_owner_lock:
            owner._file_owner_cache[os.path.normcase(path)] = (
                4321, "node.exe", time.monotonic() - FILE_OWNER_TTL_SECONDS - 1)

        self.assertIsNone(owner._file_owner_for(path), "过期条目不得再用")

    def test_empty_snapshot_is_negative(self):
        owner = self._owner()
        owner._file_owner_state()
        path = r"C://demo//none.js"

        with owner._file_owner_lock:
            owner._file_owner_cache[os.path.normcase(path)] = (0, "", time.monotonic())

        self.assertIsNone(owner._file_owner_for(path))

    def test_block_decision_prefers_early_snapshot_over_late_query(self):
        from unittest.mock import patch

        from PYAS_Realtime import RealtimeMixin

        class _Owner(_DecisionOwner, RealtimeMixin):
            """真实引擎同时具备两套 mixin:弹窗侧通过 _file_owner_for 取快照。"""

            pass

        owner = _Owner()
        path = r"C://demo//pull-requests.js"
        owner._file_owner_state()

        with owner._file_owner_lock:
            owner._file_owner_cache[os.path.normcase(path)] = (9876, "codex.exe", time.monotonic())

        with patch("PYAS_Dialog._query_file_users", return_value=[]) as late_query:
            owner.request_block_decision("File Block", source=path, detection={"name": "YARA"})
            late_query.assert_not_called()

        self.assertEqual(len(owner.submitted), 1)
        self.assertIn(9876, owner.exe_lookups, "应使用事件时刻记下的 PID")
