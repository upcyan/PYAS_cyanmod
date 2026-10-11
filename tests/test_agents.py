"""智能体指纹与监控测试:匹配规则、枚举注入、限频审计。"""
import unittest
from unittest.mock import Mock, patch

from PYAS_Agents import AgentMonitorMixin, match_agent_name


class Owner(AgentMonitorMixin):
    def __init__(self):
        self.logs = []

    def write_log(self, *args, **kwargs):
        self.logs.append((args, kwargs))


class MatchTests(unittest.TestCase):
    def test_matches_known_agents(self):
        self.assertEqual(match_agent_name('ZCode.exe'), 'ZCode')
        self.assertEqual(match_agent_name('workbuddy-agent.exe'), 'WorkBuddy')
        self.assertEqual(match_agent_name('Trae.exe'), 'Trae')
        self.assertEqual(match_agent_name('kimi-code.exe'), 'Kimi Code')
        self.assertEqual(match_agent_name('CLAUDE.EXE'), 'Claude Code')

    def test_ignores_non_agents_and_empty(self):
        self.assertIsNone(match_agent_name('explorer.exe'))
        self.assertIsNone(match_agent_name('python.exe'))
        self.assertIsNone(match_agent_name(''))
        self.assertIsNone(match_agent_name(None))

    def test_word_containment_is_case_insensitive(self):
        self.assertEqual(match_agent_name('MyAutoBotHelper.exe'), 'AutoBot')


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.owner = Owner()

    def test_scan_groups_and_logs_first_sighting(self):
        activity = self.owner.scan_agent_processes(
            lister=lambda: [('ZCode.exe', 1), ('zcode-worker.exe', 2), ('explorer.exe', 3)])
        self.assertEqual(len(activity), 1)
        self.assertEqual(activity[0]['name'], 'ZCode')
        self.assertEqual(activity[0]['count'], 2)
        self.assertEqual(activity[0]['pids'], [1, 2])
        self.assertEqual(len(self.owner.logs), 1)

    def test_repeat_scan_within_interval_does_not_relog(self):
        lister = lambda: [('Trae.exe', 9)]
        self.owner.scan_agent_processes(lister=lister)
        first = len(self.owner.logs)
        self.owner.scan_agent_processes(lister=lister)
        self.assertEqual(len(self.owner.logs), first)

    def test_get_activity_returns_last_snapshot(self):
        self.owner.scan_agent_processes(lister=lambda: [('cursor.exe', 5)])
        self.owner.scan_agent_processes(lister=lambda: [])
        self.assertEqual(self.owner.get_agent_activity(), [])

    def test_note_agent_for_path_audits_only_matches(self):
        self.assertTrue(self.owner.note_agent_for_path('C:\\tools\\ZCode\\zcode.exe'))
        self.assertFalse(self.owner.note_agent_for_path('C:\\Windows\\notepad.exe'))
        self.assertEqual(len(self.owner.logs), 1)


if __name__ == '__main__':
    unittest.main()
