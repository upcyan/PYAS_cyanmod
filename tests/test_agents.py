"""智能体指纹与监控测试:匹配规则、枚举注入、限频审计。"""
import unittest
from unittest.mock import Mock, patch

from PYAS_Agents import (AgentMonitorMixin, _endpoint_identity,
                         _match_agent_connections, match_agent_name)


class Owner(AgentMonitorMixin):
    def __init__(self):
        self.logs = []

    def write_log(self, *args, **kwargs):
        self.logs.append((args, kwargs))
    def _loc(self, texts):
        return texts.get('simplified_switch') or next(iter(texts.values()))


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

    def test_endpoint_identity_normalizes_loopback(self):
        """首见判定:回环只按主机判身份,端口翻动不算新端点;远程仍精确到端口"""
        for endpoint in ("127.0.0.1:11434", "127.0.0.1:63745", "::1:8080", "[::1]:8080",
                         "localhost:5000"):
            self.assertIn(_endpoint_identity(endpoint), ("127.0.0.1", "::1", "localhost"),
                          f"{endpoint} 应归为回环主机身份")

        self.assertEqual(_endpoint_identity("1.2.3.4:443"), "1.2.3.4:443")
        self.assertEqual(_endpoint_identity("8.8.8.8:53"), "8.8.8.8:53")
        self.assertEqual(_endpoint_identity("1.2.3.4:8443"), "1.2.3.4:8443")

    def test_loopback_port_churn_is_not_a_new_endpoint(self):
        """回环随机端口不再反复入账,远程新端点仍必须记录(负向守卫)"""

        def scan(rows):
            with patch('PYAS_Agents._query_tcp_rows', return_value=rows), \
                 patch('PYAS_Agents._process_image_path', return_value=''), \
                 patch('PYAS_Agents._process_is_elevated', return_value=False), \
                 patch('PYAS_Agents.verify_agent_identity', return_value=False):
                return self.owner.scan_agent_processes(lister=lambda: [('kimi.exe', 2)])

        def net_details():
            return [kw.get('detail', '') for (args, kw) in self.owner.logs
                    if args[1] == 'Agent Network']

        scan([('127.0.0.1', 11434, 2)])          # 首见本机服务:入账
        self.assertEqual(len(net_details()), 1)
        self.assertIn('127.0.0.1:11434', net_details()[0])

        scan([('127.0.0.1', 63745, 2)])          # 同主机新端口:不算首见
        self.assertEqual(len(net_details()), 1, '回环随机端口不该重复入账')

        scan([('203.0.113.9', 443, 2)])          # 新远程端点:必须仍入账
        self.assertEqual(len(net_details()), 2, '远程新端点必须仍被记录')

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

    def test_elevation_counts_are_recorded(self):
        with patch('PYAS_Agents._process_is_elevated', side_effect=[True, False, True]):
            activity = self.owner.scan_agent_processes(
                lister=lambda: [('claude.exe', 1), ('claude.exe', 2), ('codex.exe', 3)])
        elevated = {item['name']: item['elevated'] for item in activity}
        self.assertEqual(elevated, {'Claude Code': 1, 'ChatGPT': 1})

    def test_elevation_transition_warns_once(self):
        # 首次出现提权 → WARN;稳态复扫不重复;回落再升 → 再 WARN
        with patch('PYAS_Agents._process_is_elevated', return_value=True):
            self.owner.scan_agent_processes(lister=lambda: [('claude.exe', 1)])
        warns = [args for (args, _kw) in self.owner.logs if args[1] == 'Agent Elevated']
        self.assertEqual(len(warns), 1)

        with patch('PYAS_Agents._process_is_elevated', return_value=True):
            self.owner.scan_agent_processes(lister=lambda: [('claude.exe', 1)])
        warns = [args for (args, _kw) in self.owner.logs if args[1] == 'Agent Elevated']
        self.assertEqual(len(warns), 1)

        with patch('PYAS_Agents._process_is_elevated', return_value=False):
            self.owner.scan_agent_processes(lister=lambda: [('claude.exe', 1)])
        warns = [args for (args, _kw) in self.owner.logs if args[1] == 'Agent Elevated']
        self.assertEqual(len(warns), 1)  # 回落到未提权:静默

        with patch('PYAS_Agents._process_is_elevated', side_effect=[False, True]):
            self.owner.scan_agent_processes(lister=lambda: [('claude.exe', 1), ('claude.exe', 2)])
        warns = [args for (args, _kw) in self.owner.logs if args[1] == 'Agent Elevated']
        self.assertEqual(len(warns), 2)  # 回落后再升 → 再 WARN

    def test_elevation_query_failure_counts_as_none(self):
        with patch('PYAS_Agents._process_is_elevated', side_effect=OSError('denied')):
            activity = self.owner.scan_agent_processes(lister=lambda: [('claude.exe', 1)])
        self.assertEqual(activity[0]['elevated'], 0)

    def test_switch_off_disables_audit_but_keeps_view(self):
        self.owner.pyas_config = {"agent_switch": False}
        # 关=不审计、不标注(note_agent_for_path 返回 None),页面浏览数据仍在
        self.assertIsNone(self.owner.note_agent_for_path('C:\\tools\\ZCode\\zcode.exe'))
        with patch('PYAS_Agents._process_is_elevated', return_value=True):
            self.owner.scan_agent_processes(lister=lambda: [('claude.exe', 1)])
        self.assertEqual(len(self.owner.logs), 0)
        self.assertEqual(self.owner.get_agent_activity()[0]['name'], 'Claude Code')

    def test_identity_tier_from_signature(self):
        # 有映像路径→验签名定档;路径查不到→跳过验证(verify 收到空串按未验证)
        with patch('PYAS_Agents._process_image_path', side_effect=['', 'C:\\tools\\claude.exe']), \
             patch('PYAS_Agents.verify_agent_identity', return_value=True) as verify:
            activity = self.owner.scan_agent_processes(
                lister=lambda: [('claude.exe', 1), ('claude.exe', 2)])
        self.assertTrue(activity[0]['verified'])
        verify.assert_called_once_with('C:\\tools\\claude.exe')

        with patch('PYAS_Agents._process_image_path', return_value=''), \
             patch('PYAS_Agents.verify_agent_identity', return_value=False) as verify:
            activity = self.owner.scan_agent_processes(lister=lambda: [('kimi.exe', 7)])
        self.assertFalse(activity[0]['verified'])

    def test_identify_agent_for_event_tiers_and_switch(self):
        self.owner.pyas_config = {"agent_switch": True}
        with patch('PYAS_Agents.verify_agent_identity', return_value=True):
            product, verified = self.owner.identify_agent_for_event(
                'C:\\proj\\app.py', 'C:\\tools\\Claude\\claude.exe')
        self.assertEqual((product, verified), ('Claude Code', True))

        self.owner.pyas_config = {"agent_switch": False}
        self.assertEqual(
            self.owner.identify_agent_for_event('C:\\tools\\ZCode\\zcode.exe', ''), (None, False))

    def test_behavior_network_snapshot_and_first_seen(self):
        rows = [('1.2.3.4', 443, 1), ('127.0.0.1', 11434, 2), ('8.8.8.8', 53, 99)]
        pid_product = {1: 'Claude Code', 2: 'Kimi Code'}
        # 纯函数:只留智能体 pid 的端点
        self.assertEqual(_match_agent_connections(rows, pid_product),
                         [('Claude Code', '1.2.3.4:443'), ('Kimi Code', '127.0.0.1:11434')])

        def scan():
            with patch('PYAS_Agents._query_tcp_rows', return_value=rows), \
                 patch('PYAS_Agents._process_image_path', return_value=''), \
                 patch('PYAS_Agents._process_is_elevated', return_value=False), \
                 patch('PYAS_Agents.verify_agent_identity', return_value=False):
                return self.owner.scan_agent_processes(
                    lister=lambda: [('claude.exe', 1), ('kimi.exe', 2)])

        activity = scan()
        conns = {item['name']: item['connections'] for item in activity}
        self.assertEqual(conns['Claude Code'], [{'endpoint': '1.2.3.4:443'}])
        nets = [args for (args, _kw) in self.owner.logs if args[1] == 'Agent Network']
        self.assertEqual(len(nets), 2)  # 两个产品各一条首见端点

        scan()  # 同端点第二轮不重复记
        nets = [args for (args, _kw) in self.owner.logs if args[1] == 'Agent Network']
        self.assertEqual(len(nets), 2)

    def test_event_counter_accumulates_into_activity(self):
        self.assertTrue(self.owner.note_agent_for_path('C:\\a\\zcode.exe'))
        self.assertTrue(self.owner.note_agent_for_path('C:\\b\\zcode.exe'))

        with patch('PYAS_Agents._process_image_path', return_value=''), \
             patch('PYAS_Agents._process_is_elevated', return_value=False), \
             patch('PYAS_Agents.verify_agent_identity', return_value=False), \
             patch('PYAS_Agents._query_tcp_rows', return_value=[]):
            activity = self.owner.scan_agent_processes(lister=lambda: [('zcode.exe', 1)])

        self.assertEqual(activity[0]['events'], 2)


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
