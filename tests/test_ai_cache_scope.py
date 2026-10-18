"""AI cache/configuration trust and late-result regression tests."""
import threading
import time
import unittest
from unittest.mock import Mock, patch
import PYAS_AI as ai
from PYAS_AI import AIMixin
from PYAS_Config import ConfigMixin
from PYAS_Dialog import DialogMixin, _DecisionRequest, _ThreatPromptQueue, _WebThreatDialogSession

class App(AIMixin, DialogMixin, ConfigMixin):
    def __init__(self):
        self.lock_config = threading.RLock()
        self.lock_update = threading.RLock()
        self.pyas_config = {"ai_assist_switch": True, "ai_auto_execute": True, "ai_delay_switch": False,
            "ai_base_url": "http://a.invalid/v1", "ai_model": "A", "ai_api_key": "", "ai_api_key_enc": "",
            "ai_provider_mode": "local", "theme": "white_switch", "language": "english_switch"}
        self.save_config = Mock(return_value=True)
        self.write_log = Mock()
        self._spawn_ai_worker = Mock()

class AiCacheScopeTests(unittest.TestCase):
    def setUp(self): ai.clear_verdict_cache()
    def tearDown(self): ai.clear_verdict_cache()

    def test_complete_evidence_is_used_even_for_identical_rule_keys(self):
        rule = {"key": "same", "sha256": "a" * 64}
        a = ai.make_verdict_cache_key(rule, "file", "alert", "agent A, verified")
        b = ai.make_verdict_cache_key(rule, "file", "alert", "agent B, not verified")
        self.assertNotEqual(a, b)

    def test_endpoint_model_credential_language_and_detail_scope_cache(self):
        base = ["same", "http://a.invalid/v1", "A", "private-key-A", "file", "alert", "evidence", "english_switch"]
        variants = [list(base)]
        for index, value in ((1, "http://b.invalid/v1"), (2, "B"), (3, "private-key-B"),
                             (4, "process"), (6, "changed evidence"), (7, "simplified_switch")):
            item = list(base); item[index] = value; variants.append(item)
        with patch.object(ai, "request_ai_verdict", return_value={"verdict": "block", "reason": "fixture"}) as query:
            for args in variants:
                ai.request_ai_verdict_cached(*args)
            self.assertEqual(query.call_count, len(variants))
            cached = ai.request_ai_verdict_cached(*base)
            cached["verdict"] = "allow"
            self.assertEqual(ai.request_ai_verdict_cached(*base)["verdict"], "block")
            self.assertEqual(query.call_count, len(variants))
        keys = repr(list(ai._VERDICT_CACHE))
        self.assertNotIn("private-key-A", keys)
        self.assertNotIn("private-key-B", keys)

    def test_cancelled_request_cannot_retrieve_a_cached_allow(self):
        args = ("same", "http://a.invalid/v1", "A", "", "file", "alert", "evidence")
        with patch.object(ai, "request_ai_verdict", return_value={"verdict": "allow", "reason": "fixture"}):
            ai.request_ai_verdict_cached(*args)
            cancel = threading.Event(); cancel.set()
            self.assertIsNone(ai.request_ai_verdict_cached(*args, cancel_event=cancel))

    def test_save_invalidates_cache_and_rolls_back_failed_persistence(self):
        app = App()
        ai._cache_put("old", {"verdict": "allow", "reason": "old"})
        self.assertTrue(app.save_ai_config(model="B")["ok"])
        self.assertFalse(ai._VERDICT_CACHE)
        epoch = app._ai_config_epoch
        app.save_config.return_value = False
        self.assertFalse(app.save_ai_config(model="C")["ok"])
        self.assertEqual(app.pyas_config["ai_model"], "B")
        self.assertGreater(app._ai_config_epoch, epoch)

    def staged(self):
        app = App(); queue = _ThreatPromptQueue()
        self.addCleanup(queue.close)
        app._threat_queue = queue
        request = _DecisionRequest("english_switch", "event", "fixture", 5)
        app._start_ai_suggestion(request)
        return app, queue, request

    def test_old_model_result_is_discarded_after_configuration_change(self):
        app, queue, request = self.staged()
        def answer(*args, **kwargs):
            app.save_ai_config(model="B")
            return {"verdict": "allow", "reason": "old model"}
        with patch("PYAS_Dialog.request_ai_verdict_cached", side_effect=answer):
            app._ai_suggestion_worker(queue, request, "http://a.invalid/v1", "A", "")
        self.assertEqual(request.ai["state"], "failed")
        self.assertEqual(request.ai["verdict"], "")
        self.assertTrue(request.timeout_consumed)
        self.assertIsNone(request.deadline)
        self.assertFalse(request.done.is_set())

    def test_stale_inflight_reply_cannot_seed_a_new_configuration_generation(self):
        app, queue, first = self.staged()
        calls = []
        def answer(*args, **kwargs):
            calls.append(args[1])
            if len(calls) == 1:
                app.save_ai_config(model='B')
                app.save_ai_config(model='A')
                return {'verdict': 'allow', 'reason': 'old generation'}
            return {'verdict': 'block', 'reason': 'new generation'}
        with patch.object(ai, 'request_ai_verdict', side_effect=answer):
            app._ai_suggestion_worker(queue, first, 'http://a.invalid/v1', 'A', '')
            second = _DecisionRequest('english_switch', 'event', 'fixture', 5)
            app._start_ai_suggestion(second)
            app._ai_suggestion_worker(queue, second, 'http://a.invalid/v1', 'A', '')
        self.assertEqual(first.ai['state'], 'failed')
        self.assertEqual(len(calls), 2)
        self.assertEqual(second.ai['verdict'], 'block')

    def test_rapid_permission_revoke_and_reenable_changes_generation(self):
        app, queue, request = self.staged()
        old_epoch = request.ai_config_epoch
        self.assertFalse(app.update_config('ai_auto_execute', False))
        self.assertTrue(app.update_config('ai_auto_execute', True))
        self.assertGreater(app._ai_config_epoch, old_epoch)
        with patch('PYAS_Dialog.request_ai_verdict_cached') as query:
            app._ai_suggestion_worker(queue, request, 'http://a.invalid/v1', 'A', '')
        query.assert_not_called()
        self.assertEqual(request.ai['state'], 'failed')

    def test_revoking_auto_execute_invalidates_already_ready_advice(self):
        app, queue, request = self.staged()
        request.ai = {"state": "ready", "verdict": "allow", "reason": "old"}
        request.deadline = time.monotonic() + 5
        queue.active = request
        session = _WebThreatDialogSession("en", "fixture", "body", 5, str, queue, app)
        session.api.ready()
        app.pyas_config["ai_auto_execute"] = False
        result = session.api.snapshot()
        self.assertIsNone(request.deadline)
        self.assertTrue(request.timeout_consumed)
        self.assertEqual(request.ai["state"], "failed")
        self.assertIsNone(result["remaining"])
        self.assertFalse(request.done.is_set())

if __name__ == "__main__": unittest.main()
