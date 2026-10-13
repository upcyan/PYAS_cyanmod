"""Decision lifecycle tests: no antivirus engines or real threats are started."""
import threading
import time
import unittest
from unittest.mock import Mock

from PYAS_Dialog import (
    DialogMixin, _DecisionRequest, _ThreatDialogSession, _ThreatPromptQueue,
    WM_CLOSE, WM_TIMER, ID_COUNTDOWN_TIMER,
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
