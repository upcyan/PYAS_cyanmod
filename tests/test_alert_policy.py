import copy
import tempfile
import threading
import os
import msvcrt
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from PYAS_Decisions import (
    REPEAT_MAX_LIFETIME, REPEAT_SECONDS, REPEAT_TIERS, REPEAT_USES,
    AlertPolicyMixin, alert_identity,
)
from PYAS_Dialog import _DecisionRequest, _ThreatPromptQueue, _WebThreatDialogSession

class Owner(AlertPolicyMixin):
    def __init__(self):
        self.lock_config = threading.RLock()
        self.pyas_config = {}
        self.save_config = Mock(return_value=True)

    def _ai_auto_execute_enabled(self):
        # 快照 countdown 文案分支用;本测试不涉及 AI 自动执行
        return False

class AlertPolicyTests(unittest.TestCase):
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
        return _DecisionRequest('english_switch', 'File', 'fixture', None, rule=self.identity(), category='file')

    def test_exact_identity_and_changes(self):
        rule = self.identity()
        self.assertIsNotNone(rule)
        self.assertNotEqual(rule, self.identity(action='Process Block'))
        self.assertNotEqual(rule, self.identity(target='different'))
        self.assertNotEqual(rule, self.identity(detection='other.rule'))
        other = self.path.with_name('other.bin')
        other.write_bytes(self.path.read_bytes())
        self.assertNotEqual(rule, self.identity(source=str(other)))
        self.path.write_bytes(b'replaced contents')
        self.assertNotEqual(rule, self.identity())
        self.assertIsNone(self.identity(action='Process DLL Block'))
        self.assertIsNone(self.identity(source=str(self.path.parent)))

    def test_owned_file_lock_is_preserved_while_fingerprinting(self):
        fd = os.open(self.path, os.O_RDWR | os.O_BINARY)
        size = self.path.stat().st_size
        try:
            msvcrt.locking(fd, msvcrt.LK_NBRLCK, size)
            self.owner.lock_file_ops = threading.RLock()
            self.owner.virus_lock = {str(self.path): (fd, size)}
            rule = self.owner._make_alert_identity('File Block', str(self.path), None, 'fixture.rule')
            self.assertIsNotNone(rule)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 0)
            self.assertIsNone(self.identity(), 'another handle must still be blocked by the lock')
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, size)
            os.close(fd)

    def test_permanent_is_content_bound_and_rechecked_at_commit(self):
        request = self.request()
        self.path.write_bytes(b'changed while dialog open')
        self.assertFalse(self.owner._remember_alert_decision(request, 'permanent'))
        self.assertIsNone(self.owner._lookup_alert_decision(request.rule))
        current = self.request()
        self.assertTrue(self.owner._remember_alert_decision(current, 'permanent'))
        self.assertEqual(self.owner._lookup_alert_decision(current.rule), 'allow')
        self.path.write_bytes(b'changed again')
        self.assertIsNone(self.owner._lookup_alert_decision(self.identity()))
        self.assertTrue(self.owner.clear_alert_decisions())
        self.assertIsNone(self.owner._lookup_alert_decision(current.rule))

    def test_permanent_hits_counted_and_persisted_throttled(self):
        request = self.request()
        self.assertTrue(self.owner._remember_alert_decision(request, 'permanent'))
        entry = self.owner.pyas_config['alert_allow_rules'][0]
        self.assertEqual(entry['hits'], 0, '新建记录从 0 起算')
        self.assertGreater(entry['created'], 0, '新建记录必须带添加时间')
        self.assertNotIn('created', request.rule, '落库条目不得污染弹窗在用的 rule')

        self.owner.save_config.reset_mock()
        for _ in range(3):
            self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')
        self.assertEqual(self.owner.pyas_config['alert_allow_rules'][0]['hits'], 3)
        self.assertEqual(self.owner.save_config.call_count, 1, '首次命中落盘,后续只在内存累计')

        for _ in range(47):
            self.owner._lookup_alert_decision(request.rule)
        self.assertEqual(self.owner.pyas_config['alert_allow_rules'][0]['hits'], 50)
        self.assertEqual(self.owner.save_config.call_count, 2, '每 50 次再落盘一次')

    def test_permanent_metadata_does_not_break_identity_match(self):
        # 回归:记录带 hits/created 后若仍按整字典相等匹配,永久允许会全部失效
        request = self.request()
        self.assertTrue(self.owner._remember_alert_decision(request, 'permanent'))
        self.owner.pyas_config['alert_allow_rules'] = [
            {**request.rule, 'hits': 7, 'created': 123.0}]
        self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')
        self.assertEqual(self.owner.pyas_config['alert_allow_rules'][0]['hits'], 8)

        records = self.owner.list_release_records()
        self.assertEqual(records['permanent'][0]['hits'], 8)
        self.assertEqual(records['permanent'][0]['created'], 123.0)

    def test_legacy_permanent_rule_without_metadata_still_works(self):
        # 旧版本存的记录只有身份字段:照样放行,命中从 0 起累计
        request = self.request()
        self.owner.pyas_config['alert_allow_rules'] = [dict(request.rule)]
        self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')
        self.assertEqual(self.owner.pyas_config['alert_allow_rules'][0]['hits'], 1)

        record = self.owner.list_release_records()['permanent'][0]
        self.assertEqual(record['hits'], 1)
        self.assertEqual(record['created'], 0, '旧记录没有添加时间,前端显示占位符')

    def test_save_failure_rolls_back(self):
        request = self.request()
        self.owner.pyas_config['alert_allow_rules'] = []
        self.owner.save_config.return_value = False
        self.assertFalse(self.owner._remember_alert_decision(request, 'permanent'))
        self.assertEqual(self.owner.pyas_config['alert_allow_rules'], [])

    def test_repeat_off_by_default_and_base_expiry_use_limit(self):
        request = self.request()
        key = request.rule['key']
        self.assertTrue(self.owner._remember_alert_decision(request, 'allow'))
        self.assertIsNone(self.owner._lookup_alert_decision(request.rule))
        # 创建即基础窗口 60s,未消费则不顺延
        with patch('PYAS_Decisions.time.monotonic', return_value=100):
            self.assertTrue(self.owner._remember_alert_decision(request, 'allow', repeat=True))
        self.assertEqual(self.owner._recent_alert_decisions[key]['until'], 160)
        with patch('PYAS_Decisions.time.monotonic', return_value=160):
            self.assertIsNone(self.owner._lookup_alert_decision(request.rule))
        # 用尽次数上限:同刻消费 100 次后,第 101 次已无额度
        with patch('PYAS_Decisions.time.monotonic', return_value=200):
            self.assertTrue(self.owner._remember_alert_decision(request, 'allow', repeat=True))
            for _ in range(100):
                self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')
            self.assertIsNone(self.owner._lookup_alert_decision(request.rule))
        # 换一个决定不继承旧档位:新条目窗口回到基础档
        with patch('PYAS_Decisions.time.monotonic', return_value=300):
            self.assertTrue(self.owner._remember_alert_decision(request, 'block', repeat=True))
        self.assertEqual(self.owner._recent_alert_decisions[key]['until'], 360)
        with patch('PYAS_Decisions.time.monotonic', return_value=329):
            self.assertIsNone(self.owner._lookup_alert_decision(request.rule, uses=101))
            self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'block')

    def test_repeat_window_escalates_with_consumed_uses(self):
        """消费越多,窗口按阶梯顺延;只延长不缩短,且受绝对寿命上限约束。"""
        request = self.request()
        key = request.rule['key']

        def consume(times):
            for _ in range(times):
                self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')

        # 消费 4 次(未触档):仍为基础窗口 60s
        with patch('PYAS_Decisions.time.monotonic', return_value=1000):
            self.assertTrue(self.owner._remember_alert_decision(request, 'allow', repeat=True))
            consume(4)
        self.assertEqual(self.owner._recent_alert_decisions[key]['until'],
                         1000 + REPEAT_SECONDS)

        for floor, window in REPEAT_TIERS:
            with patch('PYAS_Decisions.time.monotonic', return_value=1000):
                self.assertTrue(self.owner._remember_alert_decision(request, 'allow', repeat=True))
                consume(floor)
            # 第 floor 次触发 window 档,顺延到创建点 + window
            self.assertEqual(self.owner._recent_alert_decisions[key]['until'], 1000 + window,
                             f'消费 {floor} 次应触发 {window}s 档')

        # 功能验证:基础窗口(1060)已过,但已升档 → 仍放行
        with patch('PYAS_Decisions.time.monotonic', return_value=1000):
            self.assertTrue(self.owner._remember_alert_decision(request, 'allow', repeat=True))
            consume(5)
        with patch('PYAS_Decisions.time.monotonic', return_value=1200):
            self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')

        # 绝对寿命上限:流持续存在、窗口一路顺延,创建满24h 仍判死
        with patch('PYAS_Decisions.time.monotonic', return_value=1000):
            self.assertTrue(self.owner._remember_alert_decision(request, 'allow', repeat=True))
            for _ in range(40):
                self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')
        # 每次都在到期前一刻再现,窗口被不断顺延,直到被寿命上限截断
        while self.owner._recent_alert_decisions[key]['until'] < 1000 + REPEAT_MAX_LIFETIME:
            moment = self.owner._recent_alert_decisions[key]['until'] - 1
            with patch('PYAS_Decisions.time.monotonic', return_value=moment):
                self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')
        capped = 1000 + REPEAT_MAX_LIFETIME
        self.assertEqual(self.owner._recent_alert_decisions[key]['until'], capped)
        with patch('PYAS_Decisions.time.monotonic', return_value=capped - 1):
            self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')
        with patch('PYAS_Decisions.time.monotonic', return_value=capped):
            self.assertIsNone(self.owner._lookup_alert_decision(request.rule))

    def test_group_snapshot_and_duplicate_resolution(self):
        queue = _ThreatPromptQueue()
        self.addCleanup(queue.close)
        first = self.request()
        first.dedup_key = (first.rule['key'], 42)
        duplicate = copy.copy(first)
        duplicate.done = threading.Event()
        duplicate.followers = []
        second = _DecisionRequest('en', 'Other file', 'fixture', None, category='file')
        third = _DecisionRequest('en', 'Network', 'fixture', None, category='network')
        queue.pending.extend([first, second, third])
        queue.take_next()
        queue.worker = object()  # Prevent a real UI worker in this fixture.
        worker = threading.Thread(target=queue.submit, args=(duplicate,))
        worker.start()
        with queue.condition:
            self.assertTrue(queue.condition.wait_for(lambda: bool(first.followers), timeout=1))
        session = _WebThreatDialogSession('en', 'test', 'test', None, str, queue, self.owner)
        data = session.api.snapshot()
        self.assertEqual(data['count'], 4)
        self.assertEqual([group['count'] for group in data['events']], [3, 1])
        self.assertTrue(session.api.decide(first.id, 'allow'))
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(duplicate.choice, 'allow')
        self.assertIs(queue.active, second)

    def test_shutdown_releases_deduplicated_waiter(self):
        queue = _ThreatPromptQueue()
        first, second = self.request(), self.request()
        first.dedup_key = second.dedup_key = ('same', 42)
        first.followers.append(second)
        queue.pending.append(first)
        queue.close()
        self.assertTrue(first.done.is_set() and second.done.is_set())
        self.assertEqual(second.choice, 'block')
