"""裁决弹窗会话的属性自洽性 + 弹窗故障回执。

背景(真实故障,2026-10-12):
`_WebThreatDialogSession.run()` 里写成了 `self.pyas_config`(实为宿主应用 owner 的属性),
每次弹出告警窗口都会在建窗那一刻抛
`AttributeError: '_WebThreatDialogSession' object has no attribute 'pyas_config'`。
`_ThreatPromptQueue._run()` 捕获后走 `finally: complete("block")` —— 也就是 fail-closed
判为"拦截",文件被写进隔离区并记 BLOCK 日志,而用户从未看到任何弹窗(静默拦截)。

本测试两条防线:
1. 真实执行 run() 的建窗段(修复前必崩),并断言会话自身确实没有 pyas_config 属性;
2. 静态 AST 校验:会话类不得读取自身未定义的 self.<attr>(通用防线,能覆盖同类新增代码);
3. 弹窗故障时必须回调 failure_notify 让用户知情,而不是无声拦截。
"""
import ast
import io
import os
import sys
import threading
import time
import types
import unittest
from unittest.mock import Mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PYAS_Dialog import (  # noqa: E402
    DialogMixin,
    _DecisionRequest,
    _ThreatPromptQueue,
    _WebThreatDialogSession,
)


class ConfigApp(DialogMixin):
    """最小宿主应用:会话所需的一切都挂在 owner 上。"""

    def __init__(self, **config):
        self.lock_config = threading.RLock()
        self.pyas_config = config
        self._window = Mock()
        self._window.get_current_url.return_value = "http://127.0.0.1:1/templates/index.html"
        self.logs = []

    def write_log(self, *args, **kwargs):
        self.logs.append((args, kwargs))
        return True


class _EventHook:
    """支持 `events.closing += handler` 的假 pywebview 事件。"""

    def __iadd__(self, handler):
        self.handler = handler
        return self


class _FakeWindow:
    def __init__(self):
        self.events = types.SimpleNamespace(closing=_EventHook())
        self.destroyed = False

    def destroy(self):
        self.destroyed = True

    def minimize(self):
        pass


class WebSessionRunTests(unittest.TestCase):
    """真实执行 run() 的建窗段 —— 此前正是在这里抛 AttributeError。"""

    def setUp(self):
        self._saved_webview = sys.modules.get("webview")
        fake = types.ModuleType("webview")
        fake.create_window = lambda *args, **kwargs: _FakeWindow()
        sys.modules["webview"] = fake

    def tearDown(self):
        if self._saved_webview is None:
            sys.modules.pop("webview", None)
        else:
            sys.modules["webview"] = self._saved_webview

    def _make_session(self, owner):
        queue = _ThreatPromptQueue()
        # 队列无待处理请求:run() 建好窗后第一轮就退出循环
        return _WebThreatDialogSession("zh", "title", "body", None, str, queue, owner)

    def test_run_builds_window_without_attribute_error(self):
        session = self._make_session(ConfigApp(theme="dark_switch"))
        session.run()  # 修复前:AttributeError: ... has no attribute 'pyas_config'
        self.assertIsNotNone(session.window)
        self.assertTrue(session.window.destroyed)

    def test_session_has_no_pyas_config_of_its_own(self):
        """主题必须取自 owner —— 会话自己不该、也确实没有 pyas_config。"""
        session = self._make_session(ConfigApp(theme="dark_switch"))
        self.assertFalse(hasattr(session, "pyas_config"))
        self.assertTrue(hasattr(session.owner, "pyas_config"))

    def test_missing_theme_in_owner_config_still_builds(self):
        """宿主配置缺 theme / 取色失败都不能拦住弹窗创建。"""
        session = self._make_session(ConfigApp())
        session.run()
        self.assertIsNotNone(session.window)


class SessionAttributeAuditTests(unittest.TestCase):
    """静态防线:会话类不得读取自身未定义的 self.<attr>。"""

    SESSION_CLASSES = ("_WebThreatDialogSession", "_ThreatDialogSession", "_WebDecisionAPI")
    DYNAMIC = {"hwnd", "window", "session", "api", "owner", "queue"}

    def test_no_undefined_self_attribute(self):
        path = os.path.join(ROOT, "PYAS_Dialog.py")
        with io.open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        offenders = []

        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or node.name not in self.SESSION_CLASSES:
                continue

            defined = set(self.DYNAMIC)
            for sub in ast.walk(node):
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    defined.add(sub.name)
                elif isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        if (isinstance(target, ast.Attribute)
                                and isinstance(target.value, ast.Name)
                                and target.value.id == "self"):
                            defined.add(target.attr)
                elif isinstance(sub, ast.AnnAssign):
                    target = sub.target
                    if (isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "self"):
                        defined.add(target.attr)

            for sub in ast.walk(node):
                # 只看 self.<attr> 这种一级读取;self.owner.xxx 的 xxx 不计入
                if (isinstance(sub, ast.Attribute)
                        and isinstance(sub.ctx, ast.Load)
                        and isinstance(sub.value, ast.Name)
                        and sub.value.id == "self"
                        and sub.attr not in defined):
                    offenders.append(f"{node.name}.{sub.attr} (L{sub.lineno})")

        self.assertEqual(
            [], sorted(set(offenders)),
            "会话类引用了自身未定义的属性(会 fail-closed 变成静默拦截): "
            + ", ".join(sorted(set(offenders))),
        )


class FailureNotifyTests(unittest.TestCase):
    """弹窗不可用时必须让用户知情,不能无声拦截。"""

    def test_window_failure_notifies_and_still_fails_closed(self):
        notified = []

        def boom(*args, **kwargs):
            raise RuntimeError("window creation failed")

        queue = _ThreatPromptQueue(
            session_factory=boom,
            failure_notify=lambda action, source, target, code: notified.append((action, source, target)),
        )
        request = _DecisionRequest("zh", "title", "body", None,
                                   action="File Block", source="C:\\x\\suspect.js")
        queue.pending.append(request)

        queue._run()

        self.assertEqual([("File Block", "C:\\x\\suspect.js", None)], notified)
        self.assertEqual("block", request.choice)
        self.assertTrue(request.done.is_set())

    def test_missing_notify_channel_does_not_break_queue(self):
        def boom(*args, **kwargs):
            raise RuntimeError("window creation failed")

        queue = _ThreatPromptQueue(session_factory=boom)
        request = _DecisionRequest("zh", "title", "body", None, action="File Block", source="C:\\x.js")
        queue.pending.append(request)

        queue._run()  # 没有回执通道也不能抛
        self.assertEqual("block", request.choice)


class DeadlineFallbackTests(unittest.TestCase):
    """倒计时到点:AI 有结论就执行其建议;AI 没结论则撤销倒计时交回用户自主决策。"""

    def setUp(self):
        self._saved_webview = sys.modules.get("webview")
        fake = types.ModuleType("webview")
        fake.create_window = lambda *args, **kwargs: _FakeWindow()
        sys.modules["webview"] = fake

    def tearDown(self):
        if self._saved_webview is None:
            sys.modules.pop("webview", None)
        else:
            sys.modules["webview"] = self._saved_webview

    def _stage(self, ai_state, timeout=5):
        owner = ConfigApp(theme="white_switch")
        queue = _ThreatPromptQueue()
        request = _DecisionRequest("zh", "title", "body", timeout)
        request.ai = ai_state
        queue.pending.append(request)
        queue.take_next()
        session = _WebThreatDialogSession("zh", "title", "body", timeout, str, queue, owner)
        session.api.ready()
        session.api.snapshot()          # 起表
        return queue, request, session

    @staticmethod
    def _wait_for(predicate, timeout=3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return False

    def _start(self, session):
        worker = threading.Thread(target=session.run, daemon=True)
        worker.start()
        return worker

    def test_no_ai_verdict_returns_decision_to_user(self):
        """AI 分析中/失败时,超时不得擅自拦截——撤销倒计时,等用户自己点。"""
        queue, request, session = self._stage({"state": "analyzing", "verdict": "", "reason": ""})
        self.assertIsNotNone(request.deadline)
        request.deadline = time.monotonic() - 1
        worker = self._start(session)
        try:
            self.assertTrue(self._wait_for(lambda: request.timeout_consumed),
                            "超时且 AI 无结论时必须消费掉倒计时")
            # 断言必须在 queue.close() 之前:close 会兜底裁决,之后 done 一定为真
            self.assertIsNone(request.deadline, "倒计时应被撤销")
            self.assertFalse(request.done.is_set(), "不得替用户裁决")
            self.assertIsNone(session.api.snapshot()["remaining"], "撤销后不得重新起表")
        finally:
            queue.close()
            worker.join(2)

    def test_ai_failure_returns_decision_to_user(self):
        """AI 判定失败(verdict 为空)同样交回用户,而不是自动拦截。"""
        queue, request, session = self._stage({"state": "failed", "verdict": "", "reason": ""})
        request.deadline = time.monotonic() - 1
        worker = self._start(session)
        try:
            self.assertTrue(self._wait_for(lambda: request.timeout_consumed))
            self.assertFalse(request.done.is_set(), "AI 失败不代表可以替用户拦截")
        finally:
            queue.close()
            worker.join(2)

    def test_ai_verdict_still_executes_on_deadline(self):
        """AI 有结论时,超时仍按建议自动裁决(该能力本身不受影响)。"""
        queue, request, session = self._stage({"state": "ready", "verdict": "allow", "reason": "ok"})
        request.deadline = time.monotonic() - 1
        worker = self._start(session)
        try:
            self.assertTrue(self._wait_for(lambda: request.done.is_set()),
                            "AI 有结论时应在到点时自动裁决")
            self.assertEqual(request.choice, "allow")
            self.assertFalse(request.timeout_consumed, "有结论时不算回退")
        finally:
            queue.close()
            worker.join(2)


if __name__ == "__main__":
    unittest.main()
