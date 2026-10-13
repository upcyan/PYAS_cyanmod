"""AI 辅助决策「延迟启动」与「取消即停」测试:不发起真实网络请求。

覆盖:
  1. 延迟窗口内用户自主决策 → 一个请求都不发(零 token 消耗)
  2. 延迟到期无人决策 → 才发起分析
  3. 关闭延迟 → 立即发起(保持原行为)
  4. 分析中被用户决策 → 取消:结果作废、不入缓存、不计用量,并 best-effort 断连
  5. 延迟秒数钳制与快照视图(倒计时标签 + 悬停说明)
"""
import threading
import time
import types
import unittest
from unittest.mock import patch

from PYAS_AI import (
    AI_DELAY_DEFAULT, AI_DELAY_MAX, AI_DELAY_MIN, clamp_ai_delay_seconds,
    request_ai_verdict, request_ai_verdict_cached,
)
import PYAS_AI
from PYAS_Dialog import (
    DialogMixin, _DecisionRequest, _ThreatPromptQueue, ai_snapshot_view,
)


class ConfigApp(DialogMixin):
    def __init__(self, **config):
        self.lock_config = threading.RLock()
        self.pyas_config = {
            'ai_assist_switch': True,
            'ai_base_url': 'http://ai.local/v1',
            'ai_api_key': '',
            'ai_model': 'test-model',
            **config,
        }


class FakeResponse:
    status_code = 200

    def json(self):
        return {
            "choices": [{"message": {"content": '{"verdict":"block","reason":"c2 beacon"}'}}],
            "usage": {"total_tokens": 42},
        }


class FakeSession:
    """可控的假 Session:post 阻塞到 release() 被调用(模拟在途请求)。"""

    instances = []

    def __init__(self):
        self.closed = False
        self.release = threading.Event()
        self.post_calls = 0
        FakeSession.instances.append(self)

    def post(self, url, **kwargs):
        self.post_calls += 1
        # 模拟真实网络:连接被另一方关闭时抛错
        while not self.release.wait(0.02):
            if self.closed:
                raise RuntimeError("connection closed by cancel")

        if self.closed:
            raise RuntimeError("connection closed by cancel")

        return FakeResponse()

    def close(self):
        self.closed = True
        self.release.set()


def wait_until(predicate, timeout=3.0, interval=0.02):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if predicate():
            return True

        time.sleep(interval)

    return predicate()


class ClampTests(unittest.TestCase):
    def test_clamps_to_range_and_falls_back(self):
        self.assertEqual(clamp_ai_delay_seconds(None), AI_DELAY_DEFAULT)
        self.assertEqual(clamp_ai_delay_seconds('abc'), AI_DELAY_DEFAULT)
        self.assertEqual(clamp_ai_delay_seconds(0), AI_DELAY_MIN)
        self.assertEqual(clamp_ai_delay_seconds(-5), AI_DELAY_MIN)
        self.assertEqual(clamp_ai_delay_seconds(999), AI_DELAY_MAX)
        self.assertEqual(clamp_ai_delay_seconds('7'), 7)
        self.assertEqual(AI_DELAY_DEFAULT, 3)


class DelayStartTests(unittest.TestCase):
    def setUp(self):
        self.queue = _ThreatPromptQueue()

    def _app(self, **config):
        app = ConfigApp(**config)
        app._threat_queue = self.queue
        return app

    def test_user_decision_inside_window_never_sends_a_request(self):
        app = self._app(ai_delay_switch=True, ai_delay_seconds=1)
        request = _DecisionRequest('english_switch', 't', 'm', None)

        with patch('PYAS_Dialog.request_ai_verdict_cached') as mocked:
            app._start_ai_suggestion(request)
            # 延迟窗口内:状态为 delay,且带有截止时间供界面倒计时
            self.assertEqual(request.ai['state'], 'delay')
            self.assertGreater(request.ai['deadline'], time.monotonic())

            time.sleep(0.15)
            request.done.set()          # 用户自主决策
            time.sleep(1.2)             # 跨过延迟窗口

            self.assertEqual(mocked.call_count, 0, '窗口内已决策就不该发起任何请求')
            self.assertEqual(request.ai['state'], 'delay', '状态保持 delay,不会被改成 analyzing')

    def test_analysis_starts_only_after_the_delay_elapses(self):
        app = self._app(ai_delay_switch=True, ai_delay_seconds=1)
        request = _DecisionRequest('english_switch', 't', 'm', None)
        started = time.monotonic()

        with patch('PYAS_Dialog.request_ai_verdict_cached',
                   return_value={'verdict': 'block', 'reason': 'beacon'}) as mocked:
            app._start_ai_suggestion(request)
            self.assertEqual(request.ai['state'], 'delay')
            self.assertEqual(mocked.call_count, 0, '延迟期内不得发请求')

            self.assertTrue(wait_until(lambda: request.ai['state'] == 'ready', timeout=4))

            self.assertGreaterEqual(time.monotonic() - started, 1.0, '必须等满延迟时间')
            self.assertEqual(mocked.call_count, 1)
            self.assertEqual(request.ai['verdict'], 'block')

    def test_disabled_delay_starts_immediately(self):
        app = self._app(ai_delay_switch=False, ai_delay_seconds=5)
        request = _DecisionRequest('english_switch', 't', 'm', None)
        started = time.monotonic()

        with patch('PYAS_Dialog.request_ai_verdict_cached',
                   return_value={'verdict': 'allow', 'reason': 'ok'}) as mocked:
            app._start_ai_suggestion(request)
            # 关闭延迟:不得进入 delay 态,直接开始分析
            self.assertNotEqual(request.ai['state'], 'delay')
            self.assertTrue(wait_until(lambda: request.ai['state'] == 'ready', timeout=2))
            self.assertEqual(mocked.call_count, 1)
            self.assertLess(time.monotonic() - started, 1.0, '关闭延迟应立刻发起,不等 5 秒')

    def test_unavailable_config_skips_delay_entirely(self):
        app = self._app(ai_delay_switch=True, ai_delay_seconds=5, ai_assist_switch=False)
        request = _DecisionRequest('english_switch', 't', 'm', None)
        app._start_ai_suggestion(request)
        self.assertEqual(request.ai['state'], 'unavailable')


class CancelOnDecideTests(unittest.TestCase):
    def test_complete_sets_cancel_and_calls_abort(self):
        queue = _ThreatPromptQueue()
        request = _DecisionRequest('english_switch', 't', 'm', None)
        aborted = []
        request.ai_abort = lambda: aborted.append(True)
        queue.active = request

        queue.complete('allow')

        self.assertTrue(request.ai_cancel.is_set())
        self.assertEqual(aborted, [True])
        self.assertTrue(request.done.is_set())
        self.assertEqual(request.choice, 'allow')

    def test_close_cancels_queued_and_active_requests(self):
        queue = _ThreatPromptQueue()
        active = _DecisionRequest('english_switch', 't', 'm', None)
        queued = _DecisionRequest('english_switch', 't2', 'm', None)
        queue.active = active
        queue.pending.append(queued)

        queue.close()

        self.assertTrue(active.ai_cancel.is_set())
        self.assertTrue(queued.ai_cancel.is_set())

    def test_worker_discards_result_when_cancelled_midflight(self):
        queue = _ThreatPromptQueue()
        app = ConfigApp()
        app._threat_queue = queue
        request = _DecisionRequest('english_switch', 't', 'm', None)
        queue.active = request

        recorded = []
        app.record_ai_token_usage = lambda model, tokens: recorded.append((model, tokens))

        def in_flight(*args, **kwargs):
            # 模拟:请求已发出,用户在这期间裁决 → 取消置位,连接被关闭
            wait_until(request.ai_cancel.is_set, timeout=2)
            raise RuntimeError("connection closed by cancel")

        with patch('PYAS_Dialog.request_ai_verdict_cached', side_effect=in_flight) as mocked:
            worker = threading.Thread(
                target=app._ai_suggestion_worker,
                args=(queue, request, 'http://ai.local/v1', 'test-model', ''),
                daemon=True,
            )
            worker.start()
            self.assertTrue(wait_until(lambda: mocked.call_count == 1, timeout=2))

            queue.complete('block')          # 用户自主决策

            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())

        # 取消后不得把结果写成就绪、不得计用量、不得改变用户裁决
        self.assertNotEqual(request.ai, {'state': 'ready', 'verdict': 'block', 'reason': 'c2 beacon'})
        self.assertEqual(recorded, [])
        self.assertEqual(request.choice, 'block')

    def test_worker_skips_state_write_when_cancelled_before_result(self):
        queue = _ThreatPromptQueue()
        app = ConfigApp()
        request = _DecisionRequest('english_switch', 't', 'm', None)
        request.ai_cancel.set()

        with patch('PYAS_Dialog.request_ai_verdict_cached',
                   return_value={'verdict': 'block', 'reason': 'r'}) as mocked:
            app._ai_suggestion_worker(queue, request, 'http://ai.local/v1', 'test-model', '')

        self.assertEqual(mocked.call_count, 1, '取消标记在调用前已置位时,函数内部会立刻返回')
        self.assertIsNone(request.ai, '取消后不得写入 ready 状态')


class AiRequestCancelTests(unittest.TestCase):
    """PYAS_AI 层面:取消语义不得留下缓存、用量或误报异常。"""

    def setUp(self):
        FakeSession.instances.clear()
        self._patch = patch.object(PYAS_AI.requests, 'Session', FakeSession)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_pre_cancelled_never_creates_a_session(self):
        cancel = threading.Event()
        cancel.set()
        self.assertIsNone(request_ai_verdict('http://ai.local/v1', 'm', '', 'c', 't', 'd',
                                             cancel_event=cancel))
        self.assertEqual(FakeSession.instances, [], '已取消时连 Session 都不该创建')

    def test_cancelled_midflight_returns_none_without_usage(self):
        cancel = threading.Event()
        holder = []
        tokens = []

        def cancel_later():
            time.sleep(0.1)
            cancel.set()

            for session in holder:
                session.close()          # 模拟决策路径关闭在途连接

        threading.Thread(target=cancel_later, daemon=True).start()
        result = request_ai_verdict('http://ai.local/v1', 'm', '', 'c', 't', 'd',
                                    usage_sink=tokens.append, cancel_event=cancel,
                                    session_holder=holder)

        self.assertIsNone(result, '连接被取消后不得返回建议')
        self.assertEqual(tokens, [], '取消后不得记录 token 用量')
        self.assertTrue(FakeSession.instances[0].closed)

    def test_normal_response_still_works_with_cancel_plumbing(self):
        cancel = threading.Event()
        holder = []
        tokens = []
        session = FakeSession.instances

        thread_result = {}

        def run():
            thread_result['value'] = request_ai_verdict(
                'http://ai.local/v1', 'm', '', 'c', 't', 'd',
                usage_sink=tokens.append, cancel_event=cancel, session_holder=holder)

        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(wait_until(lambda: session and session[0].post_calls == 1, timeout=2))
        session[0].release.set()          # 正常放行响应
        worker.join(timeout=2)

        self.assertEqual(thread_result['value'], {'verdict': 'block', 'reason': 'c2 beacon'})
        self.assertEqual(tokens, [42], '正常路径仍要按 usage 计费')

    def test_cancelled_verdict_is_not_cached(self):
        cancel = threading.Event()
        cache_key = f'test-cancel-{time.monotonic()}'

        def fake_request(*args, **kwargs):
            cancel.set()                  # 响应回来的同一刻已被取消
            return {'verdict': 'block', 'reason': 'stale'}

        with patch('PYAS_AI.request_ai_verdict', side_effect=fake_request):
            result = request_ai_verdict_cached(
                cache_key, 'http://ai.local/v1', 'm', '', 'c', 't', 'd',
                cancel_event=cancel)

        self.assertIsNone(result)
        self.assertIsNone(PYAS_AI._cache_get(cache_key), '被取消的结论不得进入缓存')


class DelaySnapshotTests(unittest.TestCase):
    def test_delay_state_becomes_countdown_label_with_hint(self):
        request = _DecisionRequest('simplified_switch', 't', 'm', None)
        request.ai = {'state': 'delay', 'deadline': time.monotonic() + 2.4}

        view = ai_snapshot_view(request)

        self.assertEqual(view['state'], 'delay')
        self.assertIn('3', view['label'], '倒计时向上取整到 3 秒')
        self.assertNotIn('{0}', view['label'], '占位符必须被替换')
        self.assertIn('token', view['hint'])
        self.assertEqual(view['verdict'], '', '延迟期不得携带任何建议')

    def test_delay_state_expired_shows_one_second_floor(self):
        request = _DecisionRequest('simplified_switch', 't', 'm', None)
        request.ai = {'state': 'delay', 'deadline': time.monotonic() - 5}
        self.assertIn('1', ai_snapshot_view(request)['label'])

    def test_countdown_ticks_down_over_time(self):
        request = _DecisionRequest('simplified_switch', 't', 'm', None)
        request.ai = {'state': 'delay', 'deadline': time.monotonic() + 3.0}

        first = ai_snapshot_view(request)['label']
        self.assertEqual(first, '3 秒后启动 AI 决策')

        time.sleep(1.05)
        second = ai_snapshot_view(request)['label']

        self.assertEqual(second, '2 秒后启动 AI 决策', '每次快照都要按 deadline 重算剩余秒数')
        self.assertNotEqual(first, second)


class AiResultNotificationTests(unittest.TestCase):
    """AI 出结果后推送通知:只在「用户未裁决 + 没在看弹窗」时发。"""

    def setUp(self):
        self.queue = _ThreatPromptQueue()
        self.app = ConfigApp()
        self.notified = []
        self.app.dispatch_notification = lambda title, body: self.notified.append((title, body))

    def _active_request(self, focused):
        request = _DecisionRequest('simplified_switch', '文件防护', 'm', None)
        self.queue.active = request
        self.queue.session = types.SimpleNamespace(focused=focused)
        return request

    def test_notifies_when_user_is_not_looking_at_dialog(self):
        request = self._active_request(focused=False)
        self.app._notify_ai_result(self.queue, request, {'verdict': 'block', 'reason': '命中 C2 名单'})

        self.assertEqual(len(self.notified), 1)
        title, body = self.notified[0]
        self.assertEqual(title, '文件防护', '标题用告警标题')
        self.assertIn('拦截', body, '必须带本地化结论')
        self.assertIn('命中 C2 名单', body, '必须带 AI 给出的原因')

    def test_silent_while_user_is_reading_the_dialog(self):
        request = self._active_request(focused=True)
        self.app._notify_ai_result(self.queue, request, {'verdict': 'allow', 'reason': '签名有效'})
        self.assertEqual(self.notified, [], '用户正看着弹窗时不得重复打扰')

    def test_silent_when_request_already_decided_or_not_active(self):
        request = self._active_request(focused=False)
        request.done.set()
        self.app._notify_ai_result(self.queue, request, {'verdict': 'block', 'reason': 'r'})
        self.assertEqual(self.notified, [])

        self.queue.active = _DecisionRequest('simplified_switch', '另一告警', 'm', None)
        self.app._notify_ai_result(self.queue, request, {'verdict': 'block', 'reason': 'r'})
        self.assertEqual(self.notified, [], '已不是当前告警时不再推送')

    def test_silent_without_usable_suggestion(self):
        request = self._active_request(focused=False)
        self.app._notify_ai_result(self.queue, request, None)
        self.assertEqual(self.notified, [])

    def test_missing_dispatch_capability_is_safe(self):
        request = self._active_request(focused=False)
        app = ConfigApp()          # 没有 dispatch_notification
        app._notify_ai_result(self.queue, request, {'verdict': 'block', 'reason': 'r'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
