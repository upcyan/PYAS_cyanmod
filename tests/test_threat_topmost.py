"""告警窗强制置顶:窗口创建后可能被别的置顶窗压下去,新告警要重新钉回最上层。

2026-10-20:用户要求拦截弹窗强制置顶,并且默认不能把焦点放在「拦截」上
(焦点在按钮上时按空格会直接触发拦截 —— 前端那条由 test_threat_ui.cjs 覆盖)。
"""
import unittest

from PYAS_Dialog import raise_topmost, _WebThreatDialogSession


class RaiseTopmostTests(unittest.TestCase):
    def test_invalid_handle_is_a_noop(self):
        self.assertFalse(raise_topmost(None))
        self.assertFalse(raise_topmost(0))

    def test_missing_window_never_raises(self):
        # 没有同名窗口时(或原生调用失败)必须安静降级,不能把告警链路带崩
        session = object.__new__(_WebThreatDialogSession)
        session._assert_topmost()


if __name__ == '__main__':
    unittest.main()
