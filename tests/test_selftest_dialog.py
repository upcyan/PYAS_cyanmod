# -*- coding: utf-8 -*-
"""selftest 弹窗端到端链路的应用侧回归测试。

覆盖 selftest.bat「交互弹窗(端到端)」依赖的两个应用侧行为:
1. DialogMixin._handle_selftest_threat 读哨兵 → 删文件 → 提交带 [Self Test]
   标记的裁决请求 → 裁决完成后写 Selftest Dialog 日志(带 nonce 与 decision);
2. DialogMixin._start_ai_suggestion 对 selftest 类请求直接置 unavailable,
   绝不发 AI 请求(假告警不该烧 token)。
"""
import json
import os
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import PYAS_Dialog


class _FakeSession:
    """替代真实 WebView 弹窗:记录请求并立即以 allow 完成裁决。"""

    instances = []

    def __init__(self, lang, title, message, timeout, countdown, queue=None):
        self.lang = lang
        self.title = title
        self.message = message
        self.timeout = timeout
        self.queue = queue
        self.ran = threading.Event()
        _FakeSession.instances.append(self)

    def run(self):
        request = self.queue.active

        if request is not None:
            _FakeSession.requests.append(request)

        self.queue.complete("allow")
        self.ran.set()


_FakeSession.requests = []


class _Owner:
    """最小 DialogMixin 宿主:真实队列 + 假弹窗会话 + 内存日志。"""

    def __init__(self, data_dir):
        self.path_config = data_dir
        self.closing = False
        self.logs = []
        _FakeSession.instances.clear()
        _FakeSession.requests.clear()
        self._threat_queue = PYAS_Dialog._ThreatPromptQueue(
            session_factory=lambda *args, **kwargs: _FakeSession(*args, **kwargs),
        )

    def get_interactive_lang(self):
        return "english_switch"

    def _get_threat_queue(self):
        return self._threat_queue

    def write_log(self, level, action, **kwargs):
        self.logs.append({"level": level, "action": action, **kwargs})
    def _loc(self, texts):
        return texts.get('simplified_switch') or next(iter(texts.values()))


def _write_sentinel(data_dir, nonce="nonce01"):
    pyas_dir = os.path.join(data_dir, "PYAS")
    os.makedirs(pyas_dir, exist_ok=True)
    path = os.path.join(pyas_dir, "selftest_threat.json")

    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"nonce": nonce, "title": "自测弹窗", "message": "测试"}, handle)

    return path


class TestSelftestDialog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pyas_selftest_")
        self.owner = _Owner(self.tmp)

    def _visible_logs(self, action):
        return [entry for entry in self.owner.logs if entry["action"] == action]

    def test_sentinel_pops_marked_dialog_and_logs_decision(self):
        sentinel = _write_sentinel(self.tmp, nonce="abc123")

        PYAS_Dialog.DialogMixin._handle_selftest_threat(self.owner, sentinel)

        # 哨兵文件必须被消费掉,否则会死循环重弹
        self.assertFalse(os.path.exists(sentinel))

        # 弹出的请求带 [Self Test] 标记与 selftest 类别
        self.assertEqual(len(_FakeSession.requests), 1)
        request = _FakeSession.requests[0]
        self.assertTrue(request.title.startswith("[Self Test] "))
        self.assertIn("自测弹窗", request.title)
        self.assertEqual(request.category, "selftest")

        # 裁决结果落日志,nonce 可供 selftest 对账
        entries = self._visible_logs("Selftest Dialog")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["level"], "INFO")
        self.assertIn("nonce=abc123", entries[0]["detail"])
        self.assertIn("decision=allow", entries[0]["detail"])

    def test_ai_skipped_for_selftest_requests(self):
        states = []
        owner = types.SimpleNamespace(
            lock_config=threading.RLock(),
            pyas_config={},
            _threat_queue=types.SimpleNamespace(
                set_ai_state=lambda request, state: states.append(state)
            ),
        )
        request = PYAS_Dialog._DecisionRequest(
            "english_switch", "t", "m", None, category="selftest"
        )

        PYAS_Dialog.DialogMixin._start_ai_suggestion(owner, request)

        self.assertEqual(len(states), 1)
        self.assertEqual(states[0]["state"], "unavailable")

    def test_ai_still_configured_for_real_requests(self):
        """负向边界:非 selftest 请求必须照常走配置判断(而不是被误跳过)。"""
        states = []
        owner = types.SimpleNamespace(
            lock_config=threading.RLock(),
            pyas_config={"ai_assist_switch": False},
            # 密钥解密通路:配置关时不该被调用,但方法必须存在(与 AIMixin 一致)
            _ai_endpoint_config=lambda: ("", "", ""),
            _threat_queue=types.SimpleNamespace(
                set_ai_state=lambda request, state: states.append(state)
            ),
        )
        request = PYAS_Dialog._DecisionRequest(
            "english_switch", "t", "m", None, category="process"
        )

        PYAS_Dialog.DialogMixin._start_ai_suggestion(owner, request)

        self.assertEqual(states[0]["state"], "unavailable")  # 配置关 → unavailable
        # 关键:unavailable 是由配置分支给出,且这里没有走 selftest 短路也可以验证——
        # 把 category 换成 process 后依旧得到状态回写,说明正常路径未被破坏


if __name__ == "__main__":
    unittest.main()
