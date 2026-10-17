"""AI 辅助决策「延迟启动」与「取消即停」测试:不发起真实网络请求。

覆盖:
  1. 延迟窗口内用户自主决策 → 一个请求都不发(零 token 消耗)
  2. 延迟到期无人决策 → 才发起分析
  3. 关闭延迟 → 立即发起(保持原行为)
  4. 分析中被用户决策 → 取消:结果作废、不入缓存、不计用量,并 best-effort 断连
  5. 延迟秒数钳制与快照视图(倒计时标签 + 悬停说明)
"""
import os
import threading
import time
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
            # 空占位改由环境变量提供:测试全程 mock AI 调用,不使用真实凭据
            'ai_api_key': os.environ.get('AI_API_KEY', ''),
            'ai_model': 'test-model',
            **config,
        }

    def _ai_endpoint_config(self):
        # 与 AIMixin 同语义的简化版:测试密钥仍走明文字段
        return (
            str(self.pyas_config.get('ai_base_url', '')).strip().rstrip('/'),
            str(self.pyas_config.get('ai_model', '')).strip(),
            str(self.pyas_config.get('ai_api_key', '')).strip(),
        )


class FakeResponse:
    status_code = 200

    def __init__(self):
        self.closed = False

    def iter_lines(self, chunk_size=512):
        # SSE 分块:先给结论内容,再给 usage,最后 DONE(与 OpenAI 兼容流式一致)
        yield rb'data: {"choices":[{"delta":{"content":"{\"verdict\":\"block\",\"reason\":\"c2 beacon\"}"}}]}'
        yield rb'data: {"choices":[],"usage":{"total_tokens":42}}'
        yield rb'data: [DONE]'

    def json(self):
        # 服务端不支持流式时的整体 JSON(回退解析路径)
        return {
            "choices": [{"message": {"content": '{"verdict":"block","reason":"c2 beacon"}'}}],
            "usage": {"total_tokens": 42},
        }

    def close(self):
        self.closed = True


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


class SlowStreamResponse:
    """模拟仍在生成的流式响应:首块之后一直阻塞,直到连接被关闭。"""

    status_code = 200

    def __init__(self):
        self.closed = False
        self.first_chunk_sent = threading.Event()

    def iter_lines(self, chunk_size=512):
        self.first_chunk_sent.set()
        yield rb'data: {"choices":[{"delta":{"content":"{\"verdict\":"}}]}'
        deadline = time.monotonic() + 5
        while not self.closed and time.monotonic() < deadline:
            time.sleep(0.01)
        yield rb'data: [DONE]'

    def close(self):
        self.closed = True


class SlowStreamSession:
    def __init__(self):
        self.response = SlowStreamResponse()
        self.closed = False

    def post(self, *args, **kwargs):
        return self.response

    def close(self):
        self.closed = True


class StreamCancelTests(unittest.TestCase):
    """流式传输下的取消:用户裁决后必须在数据块边界及时退出,不等生成完毕。"""

    def test_cancel_midstream_stops_without_waiting_for_generation(self):
        session = SlowStreamSession()
        cancel = threading.Event()
        holder = []
        tokens = []
        outcome = {}

        def run():
            outcome["value"] = request_ai_verdict(
                "http://ai.local/v1", "m", "", "c", "t", "d",
                usage_sink=tokens.append, cancel_event=cancel, session_holder=holder)

        with patch.object(PYAS_AI.requests, "Session", lambda *a, **k: session):
            started = time.monotonic()
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.assertTrue(session.response.first_chunk_sent.wait(timeout=2), "应已开始产出数据块")

            # 用户此刻裁决:置位取消 + 断开连接(等价于 queue.cancel_ai 的两步)
            cancel.set()
            for handle in holder:
                handle.close()

            worker.join(timeout=2)

        self.assertFalse(worker.is_alive(), "取消后必须及时返回,不得等模型生成完(5s)也不能挂死")
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertIsNone(outcome.get("value"), "取消后不得返回结论")
        self.assertEqual(tokens, [], "取消后不得记录用量")
        self.assertTrue(session.response.closed, "在途 response 必须被关闭")


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
    """AI 结论只显示在拦截弹窗内:就绪/失败都不得再发系统通知。"""

    def setUp(self):
        self.queue = _ThreatPromptQueue()

    def _app(self, **config):
        app = ConfigApp(**config)
        app._threat_queue = self.queue
        app.notified = []
        app.dispatch_notification = lambda title, body: app.notified.append((title, body))
        return app

    def test_ready_result_stays_inside_the_dialog(self):
        app = self._app(ai_delay_switch=False)
        request = _DecisionRequest('simplified_switch', '文件防护', 'm', None)

        with patch('PYAS_Dialog.request_ai_verdict_cached',
                   return_value={'verdict': 'block', 'reason': '命中 C2 名单'}):
            app._start_ai_suggestion(request)
            self.assertTrue(wait_until(lambda: request.ai['state'] == 'ready', timeout=4))

        self.assertEqual(request.ai['verdict'], 'block', '结论仍写入弹窗状态(按钮 + 结论面板)')
        self.assertEqual(app.notified, [], 'AI 结论只落在弹窗内,不得另发通知')

    def test_failed_result_stays_inside_the_dialog(self):
        app = self._app(ai_delay_switch=False)
        request = _DecisionRequest('simplified_switch', '文件防护', 'm', None)

        with patch('PYAS_Dialog.request_ai_verdict_cached', return_value=None):
            app._start_ai_suggestion(request)
            self.assertTrue(wait_until(lambda: request.ai['state'] == 'failed', timeout=4))

        self.assertEqual(app.notified, [], '失败态同样只由弹窗呈现,不发通知')


if __name__ == '__main__':
    unittest.main(verbosity=2)
