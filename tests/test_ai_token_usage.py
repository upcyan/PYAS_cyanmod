"""AI token 累计消耗测试:按模型分账、切换模型、重置、用量回传、落盘失败降级。"""
import threading
import unittest
from unittest.mock import patch

from PYAS_AI import AIMixin, parse_ai_verdict, request_ai_verdict, request_ai_verdict_cached


class TokenOwner(AIMixin):
    def __init__(self, persist_ok=True):
        self.lock_config = threading.RLock()
        self.pyas_config = {}
        self.persist_ok = persist_ok
        self.saved = 0
        self.logs = []

    def save_config(self):
        self.saved += 1
        return self.persist_ok

    def write_log(self, *args, **kwargs):
        self.logs.append((args, kwargs))


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = "error"

    def json(self):
        return self._payload


class _FakeSession:
    """建议请求的传输层替身。

    实现已从 requests.post 改为 Session.post(取消在途请求时需要句柄关闭连接),
    因此测试必须打在 Session 上;test_ai_connection 仍走 requests.post。
    """

    def __init__(self, response):
        self._response = response
        self.closed = False

    def post(self, *args, **kwargs):
        return self._response

    def close(self):
        self.closed = True


def _patch_verdict_transport(response):
    return patch("PYAS_AI.requests.Session", lambda *args, **kwargs: _FakeSession(response))


_VERDICT_PAYLOAD = {
    "choices": [{"message": {"content": '{"verdict":"block","reason":"hit C2 list"}'}}],
    "usage": {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150},
}


class TokenAccountingTests(unittest.TestCase):
    def test_record_and_query_per_model(self):
        owner = TokenOwner()
        owner.record_ai_token_usage("gpt-4o-mini", 150)
        owner.record_ai_token_usage("gpt-4o-mini", 90)
        owner.record_ai_token_usage("qwen2.5:7b", 42)
        state = owner.get_ai_token_usage()
        self.assertEqual(state["model"], "")
        self.assertEqual(state["usage"]["gpt-4o-mini"], {"tokens": 240, "requests": 2})
        self.assertEqual(state["usage"]["qwen2.5:7b"], {"tokens": 42, "requests": 1})
        self.assertEqual(state["total"], {"tokens": 282, "requests": 3})

    def test_switching_models_keeps_separate_counters(self):
        owner = TokenOwner()
        owner.pyas_config["ai_model"] = "model-a"
        owner.record_ai_token_usage("model-a", 100)
        owner.pyas_config["ai_model"] = "model-b"
        owner.record_ai_token_usage("model-b", 7)
        state = owner.get_ai_token_usage()
        # 当前模型只计自己的账;历史模型不串账
        self.assertEqual(state["model"], "model-b")
        self.assertEqual(state["usage"]["model-b"], {"tokens": 7, "requests": 1})
        self.assertEqual(state["usage"]["model-a"], {"tokens": 100, "requests": 1})
        self.assertEqual(state["total"]["tokens"], 107)

    def test_new_model_starts_at_zero(self):
        owner = TokenOwner()
        owner.record_ai_token_usage("old", 500)
        owner.pyas_config["ai_model"] = "brand-new"
        state = owner.get_ai_token_usage()
        self.assertNotIn("brand-new", state["usage"])
        self.assertEqual(state["total"]["tokens"], 500)

    def test_reset_specific_model_only(self):
        owner = TokenOwner()
        owner.record_ai_token_usage("a", 10)
        owner.record_ai_token_usage("b", 20)
        result = owner.reset_ai_token_usage("a")
        self.assertTrue(result["ok"])
        self.assertNotIn("a", result["usage"])
        self.assertEqual(result["usage"]["b"]["tokens"], 20)

    def test_reset_all(self):
        owner = TokenOwner()
        owner.record_ai_token_usage("a", 10)
        owner.record_ai_token_usage("b", 20)
        result = owner.reset_ai_token_usage()
        self.assertTrue(result["ok"])
        self.assertEqual(result["usage"], {})
        self.assertEqual(result["total"], {"tokens": 0, "requests": 0})

    def test_non_positive_and_garbage_inputs_ignored(self):
        owner = TokenOwner()
        self.assertFalse(owner.record_ai_token_usage("m", 0))
        self.assertFalse(owner.record_ai_token_usage("m", -5))
        self.assertFalse(owner.record_ai_token_usage("m", None))
        self.assertFalse(owner.record_ai_token_usage("m", "abc"))
        self.assertEqual(owner.pyas_config.get("ai_token_usage", {}), {})

    def test_corrupted_usage_table_self_heals(self):
        owner = TokenOwner()
        owner.pyas_config["ai_token_usage"] = "broken"
        owner.record_ai_token_usage("m", 5)
        self.assertEqual(owner.get_ai_token_usage()["usage"]["m"], {"tokens": 5, "requests": 1})

    def test_persist_failure_returns_false_and_logs(self):
        owner = TokenOwner(persist_ok=False)
        self.assertFalse(owner.record_ai_token_usage("m", 5))
        self.assertTrue(any("persist failed" in str(kwargs.get("detail", "")) for _, kwargs in owner.logs))

    def test_model_key_capped(self):
        owner = TokenOwner()
        long_name = "x" * 200
        owner.record_ai_token_usage(long_name, 1)
        self.assertIn("x" * 64, owner.get_ai_token_usage()["usage"])

    def test_empty_model_falls_back_to_unknown(self):
        owner = TokenOwner()
        owner.record_ai_token_usage("", 3)
        self.assertIn("(unknown)", owner.get_ai_token_usage()["usage"])


class UsageSinkTests(unittest.TestCase):
    def test_verdict_reports_usage_via_sink(self):
        owner = TokenOwner()
        received = []
        with _patch_verdict_transport(_FakeResponse(_VERDICT_PAYLOAD)):
            suggestion = request_ai_verdict(
                "http://x/v1", "m", "k", "file", "t", "d", "english_switch",
                usage_sink=received.append,
            )
        self.assertEqual(suggestion, {"verdict": "block", "reason": "hit C2 list"})
        self.assertEqual(received, [150])

    def test_usage_without_total_falls_back_to_parts(self):
        payload = {
            "choices": [{"message": {"content": '{"verdict":"allow","reason":"ok"}'}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
        received = []
        with _patch_verdict_transport(_FakeResponse(payload)):
            request_ai_verdict("http://x/v1", "m", "", "file", "t", "d", usage_sink=received.append)
        self.assertEqual(received, [15])

    def test_local_model_without_usage_reports_nothing(self):
        payload = {"choices": [{"message": {"content": '{"verdict":"allow","reason":"ok"}'}}]}
        received = []
        with _patch_verdict_transport(_FakeResponse(payload)):
            request_ai_verdict("http://x/v1", "m", "", "file", "t", "d", usage_sink=received.append)
        self.assertEqual(received, [])

    def test_sink_exception_never_breaks_verdict(self):
        def boom(_):
            raise RuntimeError("sink down")

        with _patch_verdict_transport(_FakeResponse(_VERDICT_PAYLOAD)):
            suggestion = request_ai_verdict("http://x/v1", "m", "k", "file", "t", "d",
                                            usage_sink=boom)
        self.assertEqual(suggestion["verdict"], "block")

    def test_cache_hit_consumes_nothing(self):
        import PYAS_AI
        PYAS_AI._VERDICT_CACHE.clear()
        received = []
        with _patch_verdict_transport(_FakeResponse(_VERDICT_PAYLOAD)):
            first = request_ai_verdict_cached("key-1", "http://x/v1", "m", "k", "file", "t", "d",
                                              usage_sink=received.append)
            second = request_ai_verdict_cached("key-1", "http://x/v1", "m", "k", "file", "t", "d",
                                               usage_sink=received.append)
        self.assertEqual(first, second)
        self.assertEqual(received, [150], "缓存命中不得重复计费")

    def test_test_connection_records_usage(self):
        owner = TokenOwner()
        owner.pyas_config.update({"ai_base_url": "http://x/v1", "ai_model": "m"})
        with patch("PYAS_AI.requests.post", return_value=_FakeResponse({
            "choices": [{"message": {"content": "pong"}}],
            "usage": {"total_tokens": 9},
        })):
            result = owner.test_ai_connection()
        self.assertTrue(result["ok"])
        self.assertEqual(owner.get_ai_token_usage()["usage"]["m"], {"tokens": 9, "requests": 1})

    def test_test_connection_failure_records_nothing(self):
        owner = TokenOwner()
        owner.pyas_config.update({"ai_base_url": "http://x/v1", "ai_model": "m"})
        with patch("PYAS_AI.requests.post", return_value=_FakeResponse({}, status_code=500)):
            self.assertFalse(owner.test_ai_connection()["ok"])
        self.assertEqual(owner.get_ai_token_usage()["usage"], {})


if __name__ == "__main__":
    unittest.main()
