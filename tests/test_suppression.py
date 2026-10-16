"""误报抑制测试:登记/命中/范围区分/过期/去重/回滚,不启动引擎。"""
import tempfile
import threading
import unittest
from pathlib import Path

from PYAS_Decisions import MAX_RULES, AlertPolicyMixin, alert_identity
from PYAS_Dialog import _DecisionRequest, _ThreatPromptQueue, _WebThreatDialogSession


class Owner(AlertPolicyMixin):
    def __init__(self):
        self.lock_config = threading.RLock()
        self.pyas_config = {}
        self.save_config = Mock(return_value=True)

    def _ai_auto_execute_enabled(self):
        # 快照 countdown 文案分支用;本测试不涉及 AI 自动执行
        return False


from unittest.mock import Mock  # noqa: E402  (Owner 上方需要,保持导入分组紧凑)


class SuppressionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'sample.bin'
        self.path.write_bytes(b'ordinary test fixture')
        self.owner = Owner()

    def identity(self, **extra):
        args = dict(action='File Block', source=str(self.path), target=None, detection='fixture.rule')
        args.update(extra)
        return alert_identity(**args)

    def request(self):
        return _DecisionRequest('english_switch', 'File', 'fixture', None,
                                rule=self.identity(), category='file')

    def test_report_registers_and_lookup_hits(self):
        request = self.request()
        self.assertTrue(self.owner._remember_suppression(request, 'dev_tool', 'my build tool', 'file_rule'))
        entries = self.owner.pyas_config['suppress_rules']
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['scope'], 'file_rule')
        self.assertEqual(entries[0]['sha256'], request.rule['sha256'])
        self.assertEqual(entries[0]['note'], 'my build tool')
        self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')
        self.assertEqual(entries[0]['hits'], 1)
        self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')
        self.assertEqual(entries[0]['hits'], 2)

    def test_l1_scope_requires_same_detection(self):
        request = self.request()
        self.owner._remember_suppression(request, 'dev_tool', '', 'file_rule')
        other_rule = dict(request.rule, detection='"other.rule"', key='changed')
        self.assertIsNone(self.owner._lookup_alert_decision(other_rule))

    def test_l2_scope_matches_any_detection(self):
        request = self.request()
        self.owner._remember_suppression(request, 'installer', '', 'file')
        other_rule = dict(request.rule, detection='"other.rule"', key='changed')
        self.assertEqual(self.owner._lookup_alert_decision(other_rule), 'allow')

    def test_expired_entries_pruned_and_ignored(self):
        request = self.request()
        self.assertTrue(self.owner._remember_suppression(request, 'other', '', 'file'))
        self.owner.pyas_config['suppress_rules'][0]['expires'] = 0
        self.assertIsNone(self.owner._lookup_alert_decision(request.rule))
        self.assertEqual(self.owner.pyas_config['suppress_rules'], [])

    def test_invalid_reason_scope_and_memory_alert_rejected(self):
        memory_request = _DecisionRequest('english_switch', 't', 'm', None)
        self.assertFalse(self.owner._remember_suppression(memory_request, 'dev_tool', '', 'file_rule'))
        request = self.request()
        self.assertFalse(self.owner._remember_suppression(request, 'malware', '', 'file_rule'))
        self.assertFalse(self.owner._remember_suppression(request, 'dev_tool', '', 'directory'))
        self.assertNotIn('suppress_rules', self.owner.pyas_config)

    def test_duplicate_report_refreshes_instead_of_duplicating(self):
        request = self.request()
        self.owner._remember_suppression(request, 'dev_tool', 'a', 'file_rule')
        self.assertTrue(self.owner._remember_suppression(request, 'installer', 'b', 'file_rule'))
        entries = self.owner.pyas_config['suppress_rules']
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['reason'], 'installer')
        self.assertEqual(entries[0]['note'], 'b')

    def test_file_replacement_rejected(self):
        request = self.request()
        self.path.write_bytes(b'changed contents')
        self.assertFalse(self.owner._remember_suppression(request, 'dev_tool', '', 'file_rule'))
        self.assertNotIn('suppress_rules', self.owner.pyas_config)

    def test_save_failure_rolls_back(self):
        request = self.request()
        self.owner.pyas_config['suppress_rules'] = []
        self.owner.save_config.return_value = False
        self.assertFalse(self.owner._remember_suppression(request, 'dev_tool', '', 'file'))
        self.assertEqual(self.owner.pyas_config['suppress_rules'], [])

    def test_cap_at_max_rules(self):
        request = self.request()
        rules = [{'id': str(i), 'scope': 'file', 'sha256': f'{i:064x}', 'detection': '',
                  'action': 'File Block', 'reason': 'other', 'note': '', 'created': 0,
                  'expires': 9e12, 'hits': 0, 'last_hit': 0, 'source': 'user'}
                 for i in range(MAX_RULES)]
        self.owner.pyas_config['suppress_rules'] = rules
        self.assertFalse(self.owner._remember_suppression(request, 'dev_tool', '', 'file'))

    def test_web_report_completes_allow(self):
        queue = _ThreatPromptQueue()
        self.addCleanup(queue.close)
        request = self.request()
        queue.pending.append(request)
        queue.take_next()
        queue.worker = object()  # 阻止真实 UI 工作线程
        session = _WebThreatDialogSession('en', 't', 'm', None, str, queue, self.owner)
        self.assertTrue(session.api.report_false_positive(request.id, 'dev_tool', 'note', 'file_rule'))
        self.assertEqual(request.choice, 'allow')
        self.assertTrue(request.done.is_set())
        self.assertEqual(len(self.owner.pyas_config['suppress_rules']), 1)

    def test_web_report_rejects_stale_and_invalid(self):
        queue = _ThreatPromptQueue()
        self.addCleanup(queue.close)
        request = self.request()
        queue.pending.append(request)
        queue.take_next()
        queue.worker = object()
        session = _WebThreatDialogSession('en', 't', 'm', None, str, queue, self.owner)
        self.assertFalse(session.api.report_false_positive('wrong-id', 'dev_tool', '', 'file_rule'))
        self.assertFalse(session.api.report_false_positive(request.id, 'nope', '', 'file_rule'))
        self.assertFalse(session.api.report_false_positive(request.id, 'dev_tool', 5, 'file_rule'))
        self.assertFalse(request.done.is_set())

    def test_snapshot_fp_visibility_follows_identity(self):
        queue = _ThreatPromptQueue()
        self.addCleanup(queue.close)
        memory_request = _DecisionRequest('english_switch', 't', 'm', None)
        file_request = self.request()
        queue.pending.extend([memory_request, file_request])
        queue.take_next()
        session = _WebThreatDialogSession('en', 't', 'm', None, str, queue, self.owner)
        self.assertIsNone(session.api.snapshot()['fp'], 'memory alert must not offer false positive reporting')
        queue.complete('block')
        queue.take_next()
        queue.worker = object()
        snapshot = session.api.snapshot()
        self.assertEqual(snapshot['fp']['button'], 'If you think this block is a false positive, click to dismiss')
        self.assertEqual([key for key, _ in snapshot['fp']['reasons']],
                         ['dev_tool', 'installer', 'enterprise', 'game_patch', 'other'])


if __name__ == '__main__':
    unittest.main()
