"""atomic_write_json 对实时防护短暂持有文件的容错。

背景(2026-10-31):Defender 反复短暂持有刚创建的 .tmp,os.replace 抛
WinError 32 —— 一次瞬时冲突曾打断特权恢复线程(未捕获异常杀死后台线程)。
要求:瞬时冲突(32/5)退避重试;非瞬时错误立即抛出;成功后不残留 .tmp。
"""
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock

import PYAS_Storage


def held_error():
    # 与真实 os.replace 失败同构:errno=13(EACCES→PermissionError),winerror=32
    return PermissionError(13, "另一个程序正在使用此文件。", None, 32)


class AtomicWriteRetryTests(unittest.TestCase):
    def test_transient_sharing_violation_is_retried(self):
        # ignore_cleanup_errors:本机实时防护会短暂持有测试写的 .tmp,
        # 清理失败不该把测试判红(eicar 套件同一惯例)
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            target = os.path.join(directory, "Preferences.json")
            attempts = []

            def flaky_replace(src, dst):
                attempts.append(dst)

                if len(attempts) == 1:
                    raise held_error()

                # 不用真 os.replace:本机 Defender 会连真替换一起拦(实测),
                # copyfile 直写目标名,绕开被重点盯防的 .pyas-*.tmp 命名模式
                shutil.copyfile(src, dst)
                os.unlink(src)

            with unittest.mock.patch.object(os, "replace", flaky_replace), \
                 unittest.mock.patch.object(PYAS_Storage.time, "sleep", lambda *_: None):
                PYAS_Storage.atomic_write_json(target, {"theme": "white_switch"})

            self.assertEqual(len(attempts), 2, "瞬时共享冲突必须重试而不是抛出")
            with open(target, encoding="utf-8") as stream:
                self.assertEqual(json.load(stream), {"theme": "white_switch"})
            self.assertEqual(
                [name for name in os.listdir(directory) if name.endswith(".tmp")],
                [],
                "成功后不得残留临时文件",
            )

    def test_persistent_failure_raises_after_budget(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            target = os.path.join(directory, "Preferences.json")
            attempts = []

            def denied(src, dst):
                attempts.append(dst)
                raise held_error()

            with unittest.mock.patch.object(os, "replace", denied), \
                 unittest.mock.patch.object(PYAS_Storage.time, "sleep", lambda *_: None):
                with self.assertRaises(PermissionError):
                    PYAS_Storage.atomic_write_json(target, {"a": 1})

            self.assertEqual(len(attempts), PYAS_Storage._REPLACE_ATTEMPTS, "重试预算用尽才放弃")
            self.assertFalse(os.path.exists(target), "目标文件不得被半写内容破坏")

    def test_non_transient_error_fails_immediately(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            target = os.path.join(directory, "Preferences.json")
            attempts = []
            slept = []

            def broken(src, dst):
                attempts.append(dst)
                # WinError 5(拒绝访问)按持久性处理:不重试,立即抛出
                raise PermissionError(13, "真实的 ACL 拒绝", None, 5)

            with unittest.mock.patch.object(os, "replace", broken), \
                 unittest.mock.patch.object(PYAS_Storage.time, "sleep", lambda *_: slept.append(1)):
                with self.assertRaises(PermissionError):
                    PYAS_Storage.atomic_write_json(target, {"a": 1})

            self.assertEqual(len(attempts), 1, "非瞬时错误不得重试")
            self.assertEqual(slept, [])


if __name__ == "__main__":
    unittest.main()
