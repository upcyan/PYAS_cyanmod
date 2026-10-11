"""AI 解析与云熔断测试:草案 JSON 解析、模型探测、连续失败退避。"""
import unittest
from unittest.mock import Mock, patch

from PYAS_AI import detect_local_models, parse_rule_drafts
from PYAS_Cloud import CloudScanner


class ParseRuleDraftsTests(unittest.TestCase):
    def test_parses_valid_strict_json(self):
        content = '{"drafts":[{"sha256":"' + 'a' * 64 + '","reason":"dev_tool","note":"compiler"}]}'
        drafts = parse_rule_drafts(content)
        self.assertEqual(len(drafts), 1)
        self.assertEqual(drafts[0]['sha256'], 'a' * 64)
        self.assertEqual(drafts[0]['reason'], 'dev_tool')

    def test_drops_invalid_hash_and_unknown_reason(self):
        content = ('{"drafts":[{"sha256":"short","reason":"dev_tool","note":"x"},'
                   '{"sha256":"' + 'b' * 64 + '","reason":"hack-tool","note":"y"},'
                   '{"sha256":"' + 'c' * 64 + '","reason":"weird","note":"z"}]}')
        drafts = parse_rule_drafts(content)
        self.assertEqual([d['sha256'] for d in drafts], ['b' * 64, 'c' * 64])
        self.assertEqual(drafts[0]['reason'], 'other')

    def test_returns_none_on_garbage(self):
        self.assertIsNone(parse_rule_drafts('no json here'))
        self.assertIsNone(parse_rule_drafts('{"drafts": "not a list"}'))
        self.assertIsNone(parse_rule_drafts(None))


class DetectModelsTests(unittest.TestCase):
    def response(self, status=200, payload=None):
        mock = Mock(status_code=status)
        mock.json = Mock(return_value=payload or {})
        return mock

    def test_collects_model_ids_sorted(self):
        payload = {'data': [{'id': 'qwen:7b'}, {'id': 'llama3'}, {'id': 'qwen:7b'}]}
        with patch('requests.get', return_value=self.response(payload=payload)):
            models = detect_local_models('http://127.0.0.1:11434/v1')
        self.assertEqual(models, ['llama3', 'qwen:7b'])

    def test_empty_on_http_error_and_bad_payload(self):
        with patch('requests.get', return_value=self.response(status=404)):
            self.assertEqual(detect_local_models('http://x/v1'), [])
        with patch('requests.get', return_value=self.response(payload={'weird': 1})):
            self.assertEqual(detect_local_models('http://x/v1'), [])
        with patch('requests.get', side_effect=OSError('down')):
            self.assertEqual(detect_local_models('http://x/v1'), [])


class CloudBreakerTests(unittest.TestCase):
    def make_scanner(self):
        scanner = CloudScanner()
        scanner._get_session = Mock(return_value=Mock())
        return scanner

    def test_reset_on_success(self):
        scanner = self.make_scanner()
        ok = Mock(status_code=200)
        with patch.object(scanner, '_get_session'):
            session = scanner._get_session()
            session.request = Mock(return_value=ok)
            scanner._request('GET', '/x', 'h', 'k')
            scanner._request('GET', '/x', 'h', 'k')
        self.assertEqual(scanner.fail_streak, 0)
        self.assertEqual(scanner.cooldown_until, 0.0)

    def test_cooldown_after_three_failures(self):
        import time
        scanner = self.make_scanner()
        bad = Mock(status_code=503)
        session = scanner._get_session()
        session.request = Mock(return_value=bad)
        for _ in range(3):
            scanner._request('GET', '/x', 'h', 'k')
        self.assertEqual(scanner.fail_streak, 3)
        self.assertGreater(scanner.cooldown_until, time.time())
        # 冷却期内直接短路,不发网络请求
        calls = session.request.call_count
        scanner._request('GET', '/x', 'h', 'k')
        self.assertEqual(session.request.call_count, calls)

    def test_success_resets_streak(self):
        scanner = self.make_scanner()
        session = scanner._get_session()
        responses = [Mock(status_code=500), Mock(status_code=500), Mock(status_code=200)]
        session.request = Mock(side_effect=responses)
        for _ in responses:
            scanner._request('GET', '/x', 'h', 'k')
        self.assertEqual(scanner.fail_streak, 0)
        self.assertEqual(scanner.cooldown_until, 0.0)


if __name__ == '__main__':
    unittest.main()
