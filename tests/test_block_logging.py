"""文件拦截必须留痕:隔离区写入不成功也不能吞掉 BLOCK 日志。

背景(真实故障,2026-10-12):
`RealtimeMixin.handle_new_file` 的拦截分支原先把写日志挂在隔离区写入结果上——
`if manage_named_list("quarantine", ..., action="add") > 0: write_log("BLOCK", ...)`。
而 `manage_named_list` 对**已在隔离区**的文件返回 0(不重复写入),于是同一文件第二次被拦截时,
弹窗照常弹出、用户照常点了"拦截",但**日志里什么都不留**。
用户看到的正是"弹窗一闪而过,日志里没有记录"。

本测试锁定:无论隔离区是否新增成功、是否抛异常,BLOCK 日志都必须落一条。
"""
import os
import sys
import threading
import unittest
from unittest.mock import Mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PYAS_Realtime import RealtimeMixin  # noqa: E402


class RealtimeBlockLogTests(unittest.TestCase):
    TARGET = r"C:\demo\sample.exe"

    def _owner(self, *, quarantined=1, block=True, raises=False, document_switch=True):
        owner = Mock()
        owner.lock_config = threading.RLock()
        owner.lock_file_ops = threading.RLock()
        owner.pyas_config = {
            "document_switch": document_switch,
            "interactive_switch": True,
        }
        owner.virus_lock = set()
        owner.safe_scan_engine = Mock(return_value={"name": "EICAR-Test"})
        owner.cloud_check = Mock()
        owner.lock_file = Mock()
        owner.request_block_decision = Mock(return_value=block)
        owner.calc_file_hash = Mock(return_value="deadbeef")
        owner.write_log = Mock()
        owner.manage_named_list = (
            Mock(side_effect=RuntimeError("quarantine unavailable"))
            if raises else Mock(return_value=quarantined)
        )
        owner._acquire_file_scan_gate = Mock(return_value=(1234, 0))
        owner.kernel32 = Mock()
        return owner

    def _blocks(self, owner):
        return [c for c in owner.write_log.call_args_list if c.args and c.args[0] == "BLOCK"]

    def test_block_always_logged_when_quarantined(self):
        owner = self._owner(quarantined=1)
        RealtimeMixin.handle_new_file(owner, self.TARGET)

        blocks = self._blocks(owner)
        self.assertEqual(1, len(blocks), "拦截必须写一条 BLOCK 日志")
        self.assertEqual("File Block", blocks[0].args[1])
        self.assertIsNone(blocks[0].kwargs.get("detail"), "正常入隔离区时不应带异常说明")

    def test_block_logged_even_when_already_quarantined(self):
        """核心回归:文件已在隔离区(写入返回 0)时,弹窗关掉也不能没有日志。"""
        owner = self._owner(quarantined=0)
        RealtimeMixin.handle_new_file(owner, self.TARGET)

        blocks = self._blocks(owner)
        self.assertEqual(1, len(blocks), "隔离区未新增也不能吞掉 BLOCK 日志")
        self.assertEqual("File Block", blocks[0].args[1])
        self.assertIn("隔离区未新增", str(blocks[0].kwargs.get("detail") or ""), "应说明未入隔离区的原因")

    def test_block_logged_even_when_quarantine_raises(self):
        """隔离区写入抛异常同样必须留痕(此前异常会绕过 write_log)。"""
        owner = self._owner(raises=True)
        RealtimeMixin.handle_new_file(owner, self.TARGET)

        blocks = self._blocks(owner)
        self.assertEqual(1, len(blocks), "隔离区写异常时仍要写 BLOCK 日志")
        self.assertIn("隔离区未新增", str(blocks[0].kwargs.get("detail") or ""))

    def test_allow_still_logged(self):
        owner = self._owner(block=False)
        RealtimeMixin.handle_new_file(owner, self.TARGET)

        allows = [c for c in owner.write_log.call_args_list if c.args and c.args[1] == "File Allow"]
        self.assertEqual(1, len(allows), "放行分支保持原有日志")
        self.assertEqual([], self._blocks(owner))

    def test_switch_off_does_no_scanning_and_no_log(self):
        owner = self._owner(document_switch=False)
        RealtimeMixin.handle_new_file(owner, self.TARGET)

        owner.safe_scan_engine.assert_not_called()
        owner.write_log.assert_not_called()


if __name__ == "__main__":
    unittest.main()
