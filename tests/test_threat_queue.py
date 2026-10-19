"""Decision lifecycle tests: no antivirus engines or real threats are started."""
import threading
import time
import unittest
from unittest.mock import Mock

from PYAS_Dialog import (
    DialogMixin, _DecisionRequest, _ThreatDialogSession, _ThreatPromptQueue,
    WM_CLOSE, WM_TIMER, ID_COUNTDOWN_TIMER,
    THREAT_WINDOW_IDLE_GRACE,
    _WebThreatDialogSession,
)


class ConfigApp(DialogMixin):
    def __init__(self, **config):
        self.lock_config = threading.RLock()
        self.pyas_config = config


class QueueTests(unittest.TestCase):
    def test_web_bridge_rejects_stale_or_invalid_decisions(self):
        owner = ConfigApp(theme='black_switch', language='simplified_switch')
        queue = _ThreatPromptQueue()
        first = _DecisionRequest('english_switch', 'first', 'first body', None)
        second = _DecisionRequest('english_switch', 'second', 'second body', 5)
        queue.pending.extend([first, second])
        queue.take_next()
        session = _WebThreatDialogSession('en', 'test', 'test', None, str, queue, owner)
        session.api.ready()
        self.assertEqual(session.api.snapshot()['theme'], 'black_switch')
        self.assertFalse(session.api.decide(first.id, 'delete'))
        self.assertTrue(session.api.decide(first.id, 'allow'))
        self.assertTrue(first.done.is_set())
        self.assertFalse(session.api.decide(first.id, 'block'))
        self.assertIsNone(second.deadline)
        self.assertEqual(session.api.snapshot()['id'], second.id)
        self.assertIsNotNone(second.deadline)
        queue.close()

    def test_web_timer_starts_only_after_ready_and_display(self):
        queue = _ThreatPromptQueue()
        request = _DecisionRequest('en', 'test', 'test', 5)
        queue.pending.append(request)
        queue.take_next()
        session = _WebThreatDialogSession('en', 'test', 'test', 5, str, queue, ConfigApp())
        session.api.snapshot()
        self.assertIsNone(request.deadline)
        session.api.ready()
        snapshot = session.api.snapshot()
        self.assertEqual(snapshot['remaining'], 5)
        # AI 无结论:倒计时过了也不吞用户点击(决定权交回用户自主决策)
        request.deadline = time.monotonic() - 1
        session.api.decide(request.id, 'allow')
        self.assertEqual(request.choice, 'allow')
        queue.close()

    def test_stale_click_rejected_only_when_ai_has_verdict(self):
        """AI 已给出结论时,过期的点击一律拒绝(那一票已由 AI 投出)。"""
        queue = _ThreatPromptQueue()
        request = _DecisionRequest('en', 'test', 'test', 5)
        request.ai = {'state': 'ready', 'verdict': 'block', 'reason': 'bad'}
        queue.pending.append(request)
        queue.take_next()
        session = _WebThreatDialogSession('en', 'test', 'test', 5, str, queue, ConfigApp())
        session.api.ready()
        session.api.snapshot()
        request.deadline = time.monotonic() - 1
        session.api.decide(request.id, 'allow')
        self.assertEqual(request.choice, 'block')
        queue.close()

    def test_web_close_only_minimizes(self):
        session = _WebThreatDialogSession('en', 'test', 'test', None, str, _ThreatPromptQueue(), ConfigApp())
        session.window = Mock()
        self.assertFalse(session._on_closing())
        session.window.minimize.assert_called_once()
        session.window.destroy.assert_not_called()

    def test_timeout_is_opt_in_including_existing_config(self):
        app = ConfigApp(interactive_timeout=5)
        self.assertIsNone(app.get_interactive_timeout())
        app.pyas_config['interactive_auto_block'] = True
        self.assertEqual(app.get_interactive_timeout(), 5)
        app.pyas_config['interactive_timeout'] = 999
        self.assertEqual(app.get_interactive_timeout(), 300)

    def test_fifo_wait_has_no_hidden_deadline(self):
        started = threading.Event()
        release = threading.Event()
        order = []
        def session_factory(*args, queue):
            class Session:
                hwnd = None
                def run(self):
                    started.set()
                    release.wait(3)
                    while queue.active:
                        order.append(queue.active.title)
                        queue.complete('allow')
                        queue.take_next()
            return Session()
        queue = _ThreatPromptQueue(session_factory)
        requests = [_DecisionRequest('english_switch', str(i), 'test', None) for i in range(3)]
        threads = []
        try:
            for i, request in enumerate(requests):
                thread = threading.Thread(target=queue.submit, args=(request,))
                threads.append(thread)
                thread.start()
                if i == 0:
                    self.assertTrue(started.wait(1))
                deadline = time.monotonic() + 1
                while queue.count != i + 1 and time.monotonic() < deadline:
                    time.sleep(.005)
                self.assertEqual(queue.count, i + 1)
            self.assertFalse(requests[0].done.wait(.1))
            release.set()
            for thread in threads:
                thread.join(2)
                self.assertFalse(thread.is_alive())
            self.assertEqual(order, ['0', '1', '2'])
            self.assertTrue(all(r.choice == 'allow' for r in requests))
        finally:
            release.set()
            queue.close()

    def test_window_idle_grace_keeps_session_reusable(self):
        """队列清空后窗口在宽限期内保活,期间新告警复用同一窗口而非重建。

        每次新建 WebView 窗口都要重新加载 threat.html(实测仅页面就 50ms+),
        用户看到的是白屏;宽限期就是给短间隔内的下一条告警留的复用窗口。
        """
        owner = ConfigApp(theme='black_switch', language='simplified_switch')
        queue = _ThreatPromptQueue()
        request = _DecisionRequest('en', 'test', 'test', None)
        queue.pending.append(request)
        queue.take_next()
        session = _WebThreatDialogSession('en', 'test', 'test', None, str, queue, owner)
        self.assertTrue(session._should_keep_alive(request), '处理中必须保活')

        idle_at = time.monotonic()
        self.assertTrue(session._should_keep_alive(None, now=idle_at), '刚清空仍在宽限期内')
        self.assertTrue(session._should_keep_alive(None, now=idle_at + THREAT_WINDOW_IDLE_GRACE - 1))
        self.assertFalse(
            session._should_keep_alive(None, now=idle_at + THREAT_WINDOW_IDLE_GRACE + 1),
            '宽限期满必须放行销毁,否则弹窗永久驻留')
        self.assertTrue(session._should_keep_alive(request), '期间又来告警会重置空窗计时')
        self.assertTrue(session._should_keep_alive(None), '重置后宽限期重新起算')
        queue.close()

    def test_snapshot_does_not_wait_on_config_lock(self):
        """弹窗快照(400ms 轮询)不得等全局配置锁。

        snapshot 在 pywebview 桥接线程上执行;一旦配置写盘/回滚持锁较久,
        界面就卡在 Loading… 且 ready 发不出去,30 秒后被看门狗判为
        「UI failed to initialize」而自动拦截 —— 线上实测发生过。
        """
        owner = ConfigApp(theme='black_switch', language='simplified_switch')
        queue = _ThreatPromptQueue()
        request = _DecisionRequest('en', 'test', 'test', None)
        queue.pending.append(request)
        queue.take_next()
        session = _WebThreatDialogSession('en', 'test', 'test', None, str, queue, owner)

        holding = threading.Event()
        release = threading.Event()

        def hold_config_lock():
            with owner.lock_config:
                holding.set()
                release.wait(3)

        holder = threading.Thread(target=hold_config_lock, daemon=True)
        holder.start()
        self.assertTrue(holding.wait(1), '另一线程应已持有配置锁(模拟配置写盘)')
        try:
            captured = []
            poller = threading.Thread(target=lambda: captured.append(session.api.snapshot()))
            poller.start()
            poller.join(1.0)
            self.assertFalse(poller.is_alive(), '快照被配置锁卡住:弹窗会停在 Loading…')
            self.assertEqual(captured[0]['theme'], 'black_switch')
            self.assertEqual(captured[0]['language'], 'simplified_switch')
        finally:
            release.set()
            holder.join(2)
        queue.close()

    def test_idle_session_promotes_new_request_without_new_worker(self):
        """空窗保留期内提交的新告警必须就地提升为当前项,不能卡在 pending 里。

        原逻辑靠 worker 循环 take_next 提升;保活后 worker 阻塞在会话里,
        若不在 submit 就地提升,这条告警会永远等不到裁决。
        """
        started = threading.Event()
        release = threading.Event()

        def session_factory(*args, queue):
            class Session:
                hwnd = True
                def run(self):
                    started.set()
                    # 模拟宽限期待命:阻塞到测试放行,窗口保持存活
                    release.wait(5)
                def post_message(self, message):
                    pass
            return Session()

        queue = _ThreatPromptQueue(session_factory)
        first = _DecisionRequest('en', 'first', 'body', None)
        second = _DecisionRequest('en', 'second', 'body', None)
        first_thread = threading.Thread(target=queue.submit, args=(first,))
        second_thread = threading.Thread(target=queue.submit, args=(second,))
        try:
            first_thread.start()
            self.assertTrue(started.wait(1))
            deadline = time.monotonic() + 1
            while queue.active is not first and time.monotonic() < deadline:
                time.sleep(.005)
            self.assertIs(queue.active, first)
            queue.complete('allow')
            self.assertTrue(first.done.is_set())

            second_thread.start()
            deadline = time.monotonic() + 1
            while queue.active is not second and time.monotonic() < deadline:
                time.sleep(.005)
            self.assertIs(queue.active, second, '空窗期内的新告警应立即成为当前项')
            queue.complete('block')
            self.assertTrue(second.done.wait(1))
        finally:
            release.set()
            queue.close()
            first_thread.join(2)
            second_thread.join(2)

    def test_shutdown_resolves_active_pending_and_capacity_waiters(self):
        started = threading.Event()
        release = threading.Event()
        def session_factory(*args, queue):
            class Session:
                hwnd = None
                def run(self):
                    started.set()
                    release.wait(3)
            return Session()
        queue = _ThreatPromptQueue(session_factory, capacity=1)
        requests = [_DecisionRequest('english_switch', str(i), 'test', None) for i in range(2)]
        threads = [threading.Thread(target=queue.submit, args=(r,)) for r in requests]
        threads[0].start()
        self.assertTrue(started.wait(1))
        threads[1].start()
        queue.close()
        release.set()
        for thread in threads:
            thread.join(2)
            self.assertFalse(thread.is_alive())
        self.assertTrue(all(r.done.is_set() and r.choice == 'block' for r in requests))

    def test_window_failure_does_not_strand_request(self):
        def session_factory(*args, queue):
            return Mock(run=Mock(return_value='block'), hwnd=None)
        queue = _ThreatPromptQueue(session_factory)
        request = _DecisionRequest('english_switch', 'test', 'test', None)
        self.assertEqual(queue.submit(request), 'block')
        self.assertTrue(request.done.is_set())
        queue.close()

    def test_factory_exception_does_not_strand_request(self):
        def session_factory(*args, **kwargs):
            raise RuntimeError('simulated construction failure')
        queue = _ThreatPromptQueue(session_factory)
        request = _DecisionRequest('english_switch', 'test', 'test', None)
        thread = threading.Thread(target=queue.submit, args=(request,))
        with unittest.mock.patch('PYAS_Dialog.log_exception'):
            thread.start()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(request.done.is_set())
        queue.close()

    def test_close_minimizes_without_decision(self):
        session = _ThreatDialogSession('english_switch', 'test', 'test', None, str)
        class FakeSession(_ThreatDialogSession):
            @property
            def user32(self):
                return api
        api = Mock()
        session.__class__ = FakeSession
        session.wndproc(123, WM_CLOSE, 0, 0)
        api.ShowWindow.assert_called_once_with(123, 6)
        api.DestroyWindow.assert_not_called()

    def test_disabled_timeout_timer_never_decides(self):
        session = _ThreatDialogSession('english_switch', 'test', 'test', None, str)
        session.update_countdown = Mock()
        session._decide = Mock()
        session.wndproc(123, WM_TIMER, ID_COUNTDOWN_TIMER, 0)
        session._decide.assert_not_called()


if __name__ == '__main__':
    unittest.main()


class ContentDedupTests(unittest.TestCase):
    """同一份文件内容的多个副本只该弹一次窗(2026-10-19:4 个 EICAR 副本弹了 4 个)。"""

    def test_identical_content_shares_one_decision(self):
        opened = threading.Event()

        class FakeSession:
            hwnd = None
            def __init__(self, *args, **kwargs): opened.set()
            def run(self): time.sleep(0.3)
            def close(self): pass

        queue = _ThreatPromptQueue(session_factory=FakeSession)
        results = []

        def submit(key, title):
            request = _DecisionRequest("english_switch", title, "body", None,
                                       dedup_key=key, action="File Block")
            results.append(queue.submit(request))

        first = threading.Thread(target=submit, args=(("same",), "first"))
        first.start()
        self.assertTrue(opened.wait(2))
        second = threading.Thread(target=submit, args=(("same",), "second"))
        second.start()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with queue.condition:
                if queue.active is not None and queue.active.followers:
                    break
            time.sleep(0.02)
        with queue.condition:
            self.assertIsNotNone(queue.active)
            self.assertEqual(len(queue.active.followers), 1, "第二份副本应作为 follower 并入同一决策")
            self.assertEqual(len(queue.pending), 0, "不应再排一条独立请求")
        queue.complete("block")
        first.join(3)
        second.join(3)
        self.assertEqual(results, ["block", "block"])
        queue.close()


class SnapshotProcessTests(unittest.TestCase):
    """文件告警查不到发起进程时要显式说明,而不是整行消失。"""

    def _session(self, action, process_name=""):
        owner = ConfigApp(theme="white_switch", language="simplified_switch")
        queue = _ThreatPromptQueue()
        request = _DecisionRequest("simplified_switch", "t", "m", None,
                                   action=action, process_name=process_name)
        queue.pending.append(request)
        queue.take_next()
        session = _WebThreatDialogSession("zh", "t", "m", None, str, queue, owner)
        session.api.ready()
        return queue, session

    def test_file_alert_without_opener_says_unidentified(self):
        queue, session = self._session("File Block")
        name = session.api.snapshot()["process"]["name"]
        self.assertIn("未识别", name)
        queue.close()

    def test_known_process_is_shown_unchanged(self):
        queue, session = self._session("File Block", process_name="python.exe")
        self.assertEqual(session.api.snapshot()["process"]["name"], "python.exe")
        queue.close()

    def test_process_alert_without_process_stays_empty(self):
        queue, session = self._session("Process Block")
        self.assertEqual(session.api.snapshot()["process"]["name"], "")
        queue.close()


if __name__ == "__main__":
    unittest.main()
