"""AI 建议接入测试:不启动杀毒引擎,不发起真实网络请求。"""
import threading
import time
import unittest
from unittest.mock import Mock, patch

from PYAS_AI import parse_ai_verdict
from PYAS_Dialog import (
    DialogMixin, _DecisionRequest, _ThreatPromptQueue, _WebThreatDialogSession,
    ai_deadline_choice, ai_snapshot_view,
)


class ConfigApp(DialogMixin):
    def __init__(self, **config):
        self.lock_config = threading.RLock()
        self.pyas_config = {
            'ai_assist_switch': False,
            'ai_base_url': 'http://ai.local/v1',
            'ai_api_key': '',
            'ai_model': 'test-model',
            **config,
        }


class ParseVerdictTests(unittest.TestCase):
    def test_plain_and_fenced_json(self):
        self.assertEqual(parse_ai_verdict('{"verdict":"block","reason":"r"}'),
                         {"verdict": "block", "reason": "r"})
        self.assertEqual(parse_ai_verdict('```json\n{"verdict":"allow","reason":"ok"}\n```'),
                         {"verdict": "allow", "reason": "ok"})

    def test_invalid_inputs_return_none(self):
        for content in (None, 123, '', 'no json here', '{"verdict":"delete","reason":"r"}',
                        '{"verdict":"allow"', '{"verdict":"allow","reason":}'):
            self.assertIsNone(parse_ai_verdict(content))

    def test_surrounding_noise_is_tolerated(self):
        self.assertEqual(parse_ai_verdict('Verdict: {"verdict":"block","reason":"r"} done'),
                         {"verdict": "block", "reason": "r"})

    def test_reason_is_trimmed_text(self):
        parsed = parse_ai_verdict('{"verdict":"allow","reason":"  padded  "}')
        self.assertEqual(parsed['reason'], 'padded')


class StarterTests(unittest.TestCase):
    def test_disabled_without_assist_or_model(self):
        app = ConfigApp()
        request = _DecisionRequest('english_switch', 't', 'm', None)
        app._threat_queue = _ThreatPromptQueue()
        app._start_ai_suggestion(request)
        self.assertEqual(request.ai['state'], 'unavailable')

        app2 = ConfigApp(ai_assist_switch=True, ai_model='')
        request2 = _DecisionRequest('english_switch', 't', 'm', None)
        app2._threat_queue = _ThreatPromptQueue()
        app2._start_ai_suggestion(request2)
        self.assertEqual(request2.ai['state'], 'unavailable')

    def test_worker_sets_ready_and_failed_without_resolving(self):
        app = ConfigApp(ai_assist_switch=True)
        queue = _ThreatPromptQueue()
        ready = _DecisionRequest('english_switch', 't', 'm', None)
        with patch('PYAS_Dialog.request_ai_verdict_cached',
                   return_value={'verdict': 'allow', 'reason': 'legit updater'}) as mocked:
            app._ai_suggestion_worker(queue, ready, 'http://ai.local/v1', 'test-model', '')
            detail = mocked.call_args[0][6]
        self.assertIn('Message:', detail)
        self.assertEqual(ready.ai, {'state': 'ready', 'verdict': 'allow', 'reason': 'legit updater'})
        # LLM 成功也绝不代替用户裁决:请求保持未决、默认拦截
        self.assertFalse(ready.done.is_set())
        self.assertEqual(ready.choice, 'block')

        failed = _DecisionRequest('english_switch', 't', 'm', None)
        with patch('PYAS_Dialog.request_ai_verdict_cached', return_value=None):
            app._ai_suggestion_worker(queue, failed, 'http://ai.local/v1', 'test-model', '')
        self.assertEqual(failed.ai['state'], 'failed')
        self.assertFalse(failed.done.is_set())
        self.assertEqual(failed.choice, 'block')
        queue.close()

    def test_worker_skips_already_decided_request(self):
        app = ConfigApp(ai_assist_switch=True)
        queue = _ThreatPromptQueue()
        request = _DecisionRequest('english_switch', 't', 'm', None)
        request.done.set()
        with patch('PYAS_Dialog.request_ai_verdict_cached') as mocked:
            app._ai_suggestion_worker(queue, request, 'http://ai.local/v1', 'test-model', '')
        mocked.assert_not_called()
        self.assertIsNone(request.ai)
        queue.close()

    def test_queue_starts_analysis_once_not_for_followers(self):
        starter = Mock()
        displayed = threading.Event()
        release = threading.Event()
        class HeldSession:
            hwnd = None
            def run(self):
                displayed.set()
                release.wait(3)
        # Deduplication must not race a real native window failing/closing on a test host.
        queue = _ThreatPromptQueue(ai_starter=starter, session_factory=lambda *a, **kw: HeldSession())
        request = _DecisionRequest('english_switch', 't', 'm', None, dedup_key=('k', 1))
        follower = _DecisionRequest('english_switch', 't', 'm', None, dedup_key=('k', 1))
        threads = []
        try:
            first = threading.Thread(target=queue.submit, args=(request,))
            threads.append(first)
            first.start()
            self.assertTrue(displayed.wait(2))
            self.assertEqual(starter.call_count, 1)
            second = threading.Thread(target=queue.submit, args=(follower,))
            threads.append(second)
            second.start()
            with queue.condition:
                self.assertTrue(queue.condition.wait_for(lambda: queue.count == 2, timeout=2))
            self.assertEqual(starter.call_count, 1)
        finally:
            queue.close()
            release.set()
            for thread in threads:
                thread.join(2)
                self.assertFalse(thread.is_alive())
            worker = queue.worker
            if worker:
                worker.join(2)
                self.assertFalse(worker.is_alive())


class DeadlineChoiceTests(unittest.TestCase):
    def test_ready_verdict_is_applied(self):
        request = _DecisionRequest('english_switch', 't', 'm', None)
        request.ai = {'state': 'ready', 'verdict': 'allow', 'reason': 'ok'}
        self.assertEqual(ai_deadline_choice(request), 'allow')
        request.ai = {'state': 'ready', 'verdict': 'block', 'reason': 'bad'}
        self.assertEqual(ai_deadline_choice(request), 'block')

    def test_no_verdict_defers_to_user_never_allows(self):
        """AI 无结论时返回 None(交回用户自主决策):既不默认放行也不擅自拦截。"""
        for state in (None, {}, {'state': 'failed', 'verdict': '', 'reason': ''},
                      {'state': 'analyzing', 'verdict': '', 'reason': ''},
                      {'state': 'ready', 'verdict': 'maybe', 'reason': ''}):
            request = _DecisionRequest('english_switch', 't', 'm', None)
            request.ai = state
            self.assertIsNone(ai_deadline_choice(request), state)


class TimeoutTests(unittest.TestCase):
    def test_ai_mode_avoids_countdown_without_auto_execute(self):
        # 现行设计:AI 辅助开启即避让超时处理;仅「超时自动执行」二级开关才接管倒计时
        app = ConfigApp(ai_assist_switch=True)
        self.assertIsNone(app.get_interactive_timeout())
        app.pyas_config['ai_auto_execute'] = True
        self.assertEqual(app.get_interactive_timeout(), 60)
        app.pyas_config['ai_auto_execute_timeout'] = 999
        self.assertEqual(app.get_interactive_timeout(), 600)
        app.pyas_config['ai_auto_execute_timeout'] = 1
        self.assertEqual(app.get_interactive_timeout(), 5)

    def test_classic_mode_still_opt_in(self):
        app = ConfigApp()
        self.assertIsNone(app.get_interactive_timeout())
        app.pyas_config['interactive_auto_block'] = True
        self.assertEqual(app.get_interactive_timeout(), 30)
        app.pyas_config['interactive_timeout'] = 999
        self.assertEqual(app.get_interactive_timeout(), 300)
        app.pyas_config['interactive_timeout'] = 1
        self.assertEqual(app.get_interactive_timeout(), 5)


class SnapshotTests(unittest.TestCase):
    def _session(self, lang='english_switch'):
        owner = ConfigApp(theme='black_switch', language=lang)
        queue = _ThreatPromptQueue()
        request = _DecisionRequest(lang, 't', 'm', None)
        queue.pending.append(request)
        queue.take_next()
        session = _WebThreatDialogSession('en', 't', 'm', None, str, queue, owner)
        session.api.ready()
        return queue, request, session

    def test_ready_state_localized(self):
        queue, request, session = self._session()
        request.ai = {'state': 'ready', 'verdict': 'allow', 'reason': 'legit'}
        view = session.api.snapshot()['ai']
        self.assertEqual(view['verdict'], 'allow')
        self.assertEqual(view['label'], 'AI suggests allowing')
        self.assertEqual(view['hint'], 'legit')
        queue.close()

    def test_states_for_failed_and_hidden(self):
        queue, request, session = self._session('simplified_switch')
        request.ai = {'state': 'failed', 'verdict': '', 'reason': ''}
        view = session.api.snapshot()['ai']
        self.assertEqual(view['label'], 'AI 建议不可用')
        self.assertIn('不会自动放行', view['hint'])
        self.assertEqual(view['verdict'], '')

        request.ai = {'state': 'unavailable', 'verdict': '', 'reason': ''}
        self.assertIsNone(session.api.snapshot()['ai'])
        request.ai = None
        self.assertIsNone(session.api.snapshot()['ai'])
        queue.close()

    def test_ai_snapshot_view_is_module_function(self):
        request = _DecisionRequest('english_switch', 't', 'm', None)
        self.assertIsNone(ai_snapshot_view(request))


class AutoExecuteCountdownTests(unittest.TestCase):
    """超时自动执行的倒计时:必须等 AI 出结论才起表,失败回退人工决策。"""

    def _session(self, timeout):
        owner = ConfigApp(theme='black_switch', language='english_switch',
                          ai_assist_switch=True, ai_auto_execute=True)
        queue = _ThreatPromptQueue()
        request = _DecisionRequest('english_switch', 't', 'm', timeout)
        queue.pending.append(request)
        queue.take_next()
        session = _WebThreatDialogSession('en', 't', 'm', timeout, str, queue, owner)
        session.api.ready()
        return queue, request, session

    def test_delay_and_analyzing_never_arm_the_countdown(self):
        for state in ('delay', 'analyzing'):
            queue, request, session = self._session(30)
            request.ai = {'state': state, 'verdict': '', 'reason': '', 'deadline': time.monotonic() + 3}
            self.assertIsNone(session.api.snapshot()['remaining'],
                              f'{state} 阶段不得起表:AI 还没结论')
            queue.close()

    def test_ready_state_arms_the_countdown(self):
        queue, request, session = self._session(30)
        request.ai = {'state': 'ready', 'verdict': 'allow', 'reason': 'ok'}
        remaining = session.api.snapshot()['remaining']
        self.assertIn(remaining, (30, 29), f'就绪后应起表,实际 {remaining}')
        queue.close()

    def test_failed_state_falls_back_to_manual(self):
        queue, request, session = self._session(30)
        request.ai = {'state': 'failed', 'verdict': '', 'reason': ''}
        remaining = session.api.snapshot()['remaining']
        self.assertIn(remaining, (30, 29), '失败也要起表,给一段人工处理窗口')
        # 到点:AI 无结论 → 撤销倒计时,交回人工(不自动拦截、更不自动放行)
        request.deadline = time.monotonic() - 1
        self.assertIsNone(ai_deadline_choice(request), '失败态到点不得自动裁决')
        queue.close()

    def test_classic_auto_block_still_arms_without_ai(self):
        owner = ConfigApp(theme='black_switch', language='english_switch',
                          interactive_auto_block=True)
        owner.pyas_config['interactive_timeout'] = 30
        queue = _ThreatPromptQueue()
        request = _DecisionRequest('english_switch', 't', 'm', 30)
        queue.pending.append(request)
        queue.take_next()
        session = _WebThreatDialogSession('en', 't', 'm', 30, str, queue, owner)
        session.api.ready()
        remaining = session.api.snapshot()['remaining']
        self.assertIn(remaining, (30, 29), '无 AI 参与时保持原自动拦截语义')
        queue.close()


class SetAiStateTests(unittest.TestCase):
    def test_no_late_writes_after_decision(self):
        queue = _ThreatPromptQueue()
        request = _DecisionRequest('english_switch', 't', 'm', None)
        request.done.set()
        queue.set_ai_state(request, {'state': 'ready', 'verdict': 'allow', 'reason': ''})
        self.assertIsNone(request.ai)
        queue.close()


if __name__ == '__main__':
    unittest.main()
