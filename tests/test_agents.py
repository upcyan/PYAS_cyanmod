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
        # AutoBot 是早期笔误,产品实为 AutoClaw(界面图标同名)
        self.assertEqual(match_agent_name('MyAutoClawHelper.exe'), 'AutoClaw')
        self.assertEqual(match_agent_name('AUTOCLAW.EXE'), 'AutoClaw')


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


class InstalledAgentsTests(unittest.TestCase):
    """已安装过滤:L1 进程 > L2 快捷方式/npm > 安装位置,按目录顺序返回。"""

    def _list(self, processes=(), shortcuts=(), npm=(), paths=()):
        with patch('PYAS_Agents.enumerate_process_names', return_value=list(processes)), \
             patch('PYAS_Agents._scan_shortcut_names', return_value=list(shortcuts)), \
             patch('PYAS_Agents._scan_npm_bin_names', return_value=list(npm)), \
             patch('PYAS_Agents._probe_install_paths',
                   side_effect=lambda entry: entry['name'] in set(paths)):
            return Owner().list_installed_agents()

    def test_process_signal_is_strongest(self):
        result = self._list(processes=[('ZCode.exe', 1), ('explorer.exe', 2)])
        self.assertEqual([item['name'] for item in result], ['ZCode'])
        self.assertEqual(result[0]['via'], 'process')
        self.assertEqual(result[0]['logo'], 'zcode.png')
        self.assertEqual(result[0]['letter'], 'Z')
        self.assertTrue(result[0]['color'].startswith('#'))

    def test_shortcut_and_npm_signals(self):
        result = self._list(shortcuts=['trae cn'], npm=['kimi-code'])
        by_name = {item['name']: item['via'] for item in result}
        self.assertEqual(by_name.get('Trae'), 'shortcut')
        self.assertEqual(by_name.get('Kimi Code'), 'npm')

    def test_path_signal_fallback(self):
        result = self._list(paths=['Cursor'])
        self.assertEqual([item['name'] for item in result], ['Cursor'])
        self.assertEqual(result[0]['via'], 'path')

    def test_empty_machine_returns_empty(self):
        self.assertEqual(self._list(), [])

    def test_results_follow_catalog_order(self):
        result = self._list(paths=['Cursor', 'ZCode', 'Aider'])
        names = [item['name'] for item in result]
        from PYAS_Agents import AGENT_CATALOG
        expect = [e['name'] for e in AGENT_CATALOG if e['name'] in {'Cursor', 'ZCode', 'Aider'}]
        self.assertEqual(names, expect)

    def test_logoless_entry_keeps_letter_badge_fields(self):
        result = self._list(paths=['Aider'])
        self.assertEqual(result[0]['name'], 'Aider')
        self.assertIsNone(result[0]['logo'])
        self.assertEqual(result[0]['letter'], 'Ai')


if __name__ == '__main__':
    unittest.main()
