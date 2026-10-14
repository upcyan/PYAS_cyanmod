"""抑制规则管理与 L3 签名抑制测试:列表/删除/AI 草案流转/签名锚定,不启动引擎。"""
import json
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from PYAS_Decisions import AlertPolicyMixin, file_signer_hash


class Owner(AlertPolicyMixin):
    def __init__(self):
        self.lock_config = threading.RLock()
        self.pyas_config = {}
        self.save_config = Mock(return_value=True)
        self.logs = []
        self._ai_endpoint_config = lambda: ('', '', '')

    def write_log(self, *args, **kwargs):
        self.logs.append((args, kwargs))


class SuppressionManagementTests(unittest.TestCase):
    def setUp(self):
        self.owner = Owner()
        self.owner.pyas_config['suppress_rules'] = [
            {'id': 'a1', 'scope': 'file', 'sha256': 'f' * 64, 'signer': '',
             'reason': 'dev_tool', 'note': 'build tool', 'created': 100, 'expires': 9e12,
             'hits': 3, 'last_hit': 0, 'source': 'user'},
            {'id': 'old', 'scope': 'file', 'sha256': 'e' * 64, 'signer': '',
             'reason': 'other', 'note': '', 'created': 50, 'expires': 1, 'hits': 0,
             'last_hit': 0, 'source': 'user'},
        ]

    def test_get_returns_active_sorted_and_purges_expired(self):
        rules = self.owner.get_suppression_rules()
        self.assertEqual([r['id'] for r in rules], ['a1'])
        self.assertEqual(self.owner.pyas_config['suppress_rules'][0]['id'], 'a1')

    def test_delete_removes_by_id_and_persists(self):
        self.assertTrue(self.owner.delete_suppression_rule('a1'))
        self.assertEqual([r['id'] for r in self.owner.pyas_config['suppress_rules']], ['old'])
        self.assertFalse(self.owner.delete_suppression_rule('missing'))
        self.owner.save_config.return_value = False
        self.owner.pyas_config['suppress_rules'] = [{'id': 'a1', 'expires': 9e12}]
        self.assertFalse(self.owner.delete_suppression_rule('a1'))
        self.assertEqual(len(self.owner.pyas_config['suppress_rules']), 1)


class DraftFlowTests(unittest.TestCase):
    def setUp(self):
        self.owner = Owner()
        self.owner.pyas_config['suppress_rules'] = []

    def seed_logs(self):
        self.owner.logs_data = [
            {'action': 'Alert Decision Remembered', 'detail': 'File Block / t.exe / allow / repeat=False',
             'file_hash': 'a' * 64, 'source': 'C:\\t.exe'},
            {'action': 'Alert Decision Remembered', 'detail': 'File Block / t.exe / block / repeat=False',
             'file_hash': 'a' * 64, 'source': 'C:\\t.exe'},
            {'action': 'Config Update', 'detail': 'unrelated', 'file_hash': '', 'source': ''},
        ]

    def test_generate_rejects_missing_model(self):
        result = self.owner.generate_ai_rule_drafts()
        self.assertFalse(result['ok'])
        self.assertEqual(result['error'], 'missing_config')

    def test_generate_collects_allows_and_adds_drafts(self):
        self.seed_logs()
        self.owner._ai_endpoint_config = lambda: ('http://x/v1', 'm', '')
        drafts = [{'sha256': 'a' * 64, 'reason': 'dev_tool', 'note': 'compiler'}]
        with patch('PYAS_AI.request_rule_drafts', return_value=drafts):
            result = self.owner.generate_ai_rule_drafts()
        self.assertTrue(result['ok'])
        self.assertEqual(result['added'], 1)
        stored = self.owner.pyas_config['ai_rule_drafts'][0]
        self.assertEqual(stored['sha256'], 'a' * 64)
        self.assertEqual(stored['status'], 'pending')

    def test_generate_skips_duplicates_and_invalid(self):
        self.seed_logs()
        self.owner._ai_endpoint_config = lambda: ('http://x/v1', 'm', '')
        self.owner.pyas_config['suppress_rules'] = [
            {'id': 'x', 'scope': 'file', 'sha256': 'a' * 64, 'expires': 9e12}]
        drafts = [{'sha256': 'a' * 64, 'reason': 'dev_tool', 'note': 'dup'}]
        with patch('PYAS_AI.request_rule_drafts', return_value=drafts):
            result = self.owner.generate_ai_rule_drafts()
        self.assertEqual(result['added'], 0)
        self.assertEqual(self.owner.pyas_config.get('ai_rule_drafts', []), [])

    def test_resolve_approve_converts_to_file_scope_rule(self):
        self.owner.pyas_config['ai_rule_drafts'] = [
            {'id': 'd1', 'sha256': 'b' * 64, 'reason': 'installer', 'note': 'setup',
             'action': 'File Block', 'created': 1, 'status': 'pending'}]
        self.assertTrue(self.owner.resolve_ai_rule_draft('d1', True))
        rules = self.owner.pyas_config['suppress_rules']
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]['scope'], 'file')
        self.assertEqual(rules[0]['source'], 'ai')
        self.assertEqual(self.owner.pyas_config.get('ai_rule_drafts', []), [])

    def test_resolve_reject_removes_draft_only(self):
        self.owner.pyas_config['ai_rule_drafts'] = [
            {'id': 'd2', 'sha256': 'c' * 64, 'reason': 'other', 'note': '', 'created': 1}]
        self.assertTrue(self.owner.resolve_ai_rule_draft('d2', False))
        self.assertEqual(self.owner.pyas_config['suppress_rules'], [])
        self.assertFalse(self.owner.resolve_ai_rule_draft('missing', True))


class SignerScopeTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'signed.exe'
        self.path.write_bytes(b'signed fixture bytes')
        self.owner = Owner()
        self.owner.pyas_config['suppress_rules'] = []

    def request(self):
        from PYAS_Decisions import alert_identity
        rule = alert_identity(action='File Block', source=str(self.path),
            target=None, detection='vendor.sdk')
        return Mock(rule=rule, done=Mock(is_set=Mock(return_value=False)),
            deadline=None, detection='{}')

    def test_signer_scope_roundtrip_and_match(self):
        with patch('PYAS_Decisions.file_signer_hash', return_value='A' * 40):
            self.assertTrue(self.owner._remember_suppression(
                self.request(), 'dev_tool', 'vendor sdk', 'signer'))
        entry = self.owner.pyas_config['suppress_rules'][0]
        self.assertEqual(entry['scope'], 'signer')
        self.assertEqual(entry['signer'], 'A' * 40)
        self.owner._signer_hash_cache.clear()
        with patch('PYAS_Decisions.file_signer_hash', return_value='A' * 40):
            self.assertIsNotNone(self.owner._match_suppression_locked(self.request().rule))

    def test_signer_scope_requires_signature(self):
        with patch('PYAS_Decisions.file_signer_hash', return_value=None):
            self.assertFalse(self.owner._remember_suppression(
                self.request(), 'dev_tool', '', 'signer'))
        self.assertEqual(self.owner.pyas_config['suppress_rules'], [])

    def test_signer_mismatch_does_not_match(self):
        with patch('PYAS_Decisions.file_signer_hash', return_value='B' * 40):
            self.owner._remember_suppression(self.request(), 'dev_tool', '', 'signer')
        self.owner._signer_hash_cache.clear()
        with patch('PYAS_Decisions.file_signer_hash', return_value='C' * 40):
            self.assertIsNone(self.owner._match_suppression_locked(self.request().rule))

    def test_file_signer_hash_non_windows_returns_none(self):
        import os
        if os.name == 'nt':
            self.skipTest('non-Windows behaviour only')
        self.assertIsNone(file_signer_hash('anything'))


if __name__ == '__main__':
    unittest.main()
