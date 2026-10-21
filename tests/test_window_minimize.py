"""任务栏「点一下收起」:无边框窗口收不到 SC_MINIMIZE,由 WindowHook 自己接管。

2026-10-20:用户反馈点任务栏按钮不会最小化。根因是 frameless 窗口没有
WS_MINIMIZEBOX,WinForms 对 SC_MINIMIZE 直接忽略(探针实测:补样式位/托管
MinimizeBox 都不行,只能自己处理这条消息)。
"""
import threading
import time
import unittest

import PYAS


class _Window:
    width, height = 980.0, 670.0

    def __init__(self):
        self.resizes = []

    def resize(self, width, height):
        self.resizes.append((width, height))


class _Api:
    def __init__(self):
        self.calls = []
        self._maximized = False
        self.ui_queue = _Queue()
        self._window = _Window()

    def minimize(self):
        self.calls.append("minimize")

    def hide_window(self):
        self.calls.append("hide")


class _Queue:
    def put(self, value):
        pass


class TaskbarMinimizeTests(unittest.TestCase):
    def _hook(self):
        api = _Api()
        return PYAS.WindowHook("PYAS", api), api

    def test_sc_minimize_uses_application_minimize(self):
        hook, api = self._hook()
        hook.wndproc(0x1234, hook.WM_SYSCOMMAND, hook.SC_MINIMIZE, 0)

        deadline = time.monotonic() + 2.0
        while not api.calls and time.monotonic() < deadline:
            time.sleep(0.01)

        self.assertEqual(api.calls, ["minimize"], "必须走应用自己的 minimize(还原尺寸才不丢)")

    def test_restore_triggers_same_size_resync(self):
        # 还原后要主动走一次等尺寸 resize,否则 WebView2 可能先按占位尺寸画一帧
        hook, api = self._hook()
        hook.wndproc(0x1234, hook.WM_SYSCOMMAND, hook.SC_RESTORE, 0)

        deadline = time.monotonic() + 2.0
        while not api._window.resizes and time.monotonic() < deadline:
            time.sleep(0.01)

        self.assertEqual(api._window.resizes, [(980, 670)])

    def test_other_syscommands_are_not_swallowed(self):
        hook, api = self._hook()
        # SC_MAXIMIZE 只更新状态,不应触发 minimize
        hook.wndproc(0x1234, hook.WM_SYSCOMMAND, hook.SC_MAXIMIZE, 0)
        time.sleep(0.05)
        self.assertEqual(api.calls, [])
        self.assertTrue(api._maximized)


if __name__ == "__main__":
    unittest.main()
