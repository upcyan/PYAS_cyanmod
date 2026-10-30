"""蜜罐文档与 AMSI 扫描通道的行为约束(独立模块,fail-safe)。"""

import io
import os
import sys
import threading
import unittest
import zipfile

sys.path.insert(0, ".")

from PYAS_Canary import CanaryMixin, _canary_docx_bytes, CANARY_NAMES


class CanaryHost(CanaryMixin):
    def __init__(self, config=None):
        self.lock_config = threading.RLock()
        self.pyas_config = config if config is not None else {"canary_switch": True}
        self.path_user = ""
        self.logs = []
        self.rollbacks = []

    def write_log(self, *args, **kwargs):
        self.logs.append((args, kwargs))

    def _loc(self, texts):
        return texts.get("simplified_switch") or next(iter(texts.values()))

    def _behavior_maybe_rollback(self, pid):
        self.rollbacks.append(pid)


class CanaryTests(unittest.TestCase):
    def test_docx_is_valid_zip_with_declaration(self):
        data = _canary_docx_bytes()
        archive = zipfile.ZipFile(io.BytesIO(data))

        self.assertIn("word/document.xml", archive.namelist())
        document = archive.read("word/document.xml").decode("utf-8")
        self.assertIn("PYAS", document, "文档内容必须内嵌 PYAS 声明,防止用户误认为真实文档")

    def test_trigger_fires_once_per_pid_with_rollback(self):
        host = CanaryHost()
        host.path_user = ""  # 布点仅依赖 shell 文件夹;触发走集合匹配

        host._canary_path_cache = {
            os.path.normcase("C:\\Users\\u\\Desktop\\财务报表_2026.docx"): ("x", b""),
        }
        host._canary_cache_stamp = float("inf")  # 锁定缓存,避免依赖 shell 调用

        canary_path = os.path.normcase("C:\\Users\\u\\Desktop\\财务报表_2026.docx")

        class _Pid:
            def get(self, pid):
                return ("encryptor.exe", "")

        host._etw_pid_info = type("P", (), {"get": lambda self, pid: _Pid().get(pid)})()

        host._canary_on_write(9, canary_path)
        host._canary_on_write(9, canary_path)  # 冷却期内:不重复告警
        host._canary_on_write(10, canary_path)  # 另一进程:独立告警

        alerts = [log for log in host.logs if log[0][1] == "Canary Triggered"]
        self.assertEqual(len(alerts), 2, "同进程 60 秒冷却,跨进程独立")
        self.assertEqual(host.rollbacks, [9, 10], "命中必须触发与 L3 同款的回滚挂钩")

    def test_switch_off_disables_entirely(self):
        host = CanaryHost({"canary_switch": False})
        host._canary_path_cache = {"x": ("x", b"")}
        host._canary_cache_stamp = float("inf")

        host._canary_on_write(9, "x")

        self.assertEqual(host.logs, [], "开关关闭时不告警")
        self.assertEqual(host.rollbacks, [])

    def test_non_canary_path_is_zero_cost(self):
        host = CanaryHost()
        host._canary_path_cache = {"x": ("x", b"")}
        host._canary_cache_stamp = float("inf")

        host._canary_on_write(9, "C:\\Users\\u\\real-document.docx")

        self.assertEqual(host.logs, [])
        self.assertEqual(host.rollbacks, [])

    def test_exception_in_trigger_never_propagates(self):
        """主链路上的挂钩绝不抛出:write_log 炸了也必须静默消化。"""
        host = CanaryHost()
        host._canary_path_cache = {
            os.path.normcase("C:\\x\\财务报表_2026.docx"): ("x", b""),
        }
        host._canary_cache_stamp = float("inf")

        def boom(*args, **kwargs):
            raise RuntimeError("log sink broken")

        host.write_log = boom

        host._canary_on_write(9, os.path.normcase("C:\\x\\财务报表_2026.docx"))
        self.assertTrue(True, "未抛异常即通过")


class AmsiChannelTests(unittest.TestCase):
    def test_module_smoke_on_this_machine(self):
        """本机冒烟:通道可用时干净内容必须 NOT_DETECTED。"""
        from PYAS_Amsi import get_scanner

        outcome = get_scanner().scan_bytes(b"console.log('hello');", "smoke.js")

        if outcome is None:
            self.skipTest("本机无 AMSI provider")
        self.assertFalse(outcome[0], "无害脚本不得判恶意")

    def test_scan_file_missing_returns_none(self):
        from PYAS_Amsi import get_scanner

        self.assertIsNone(get_scanner().scan_file("Z:\\no\\such\\file.js"))


if __name__ == "__main__":
    unittest.main()
