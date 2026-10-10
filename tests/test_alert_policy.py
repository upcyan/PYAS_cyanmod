import copy
import tempfile
import threading
import os
import msvcrt
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from PYAS_Decisions import AlertPolicyMixin, alert_identity
from PYAS_Dialog import _DecisionRequest, _ThreatPromptQueue, _WebThreatDialogSession

class Owner(AlertPolicyMixin):
    def __init__(self):
        self.lock_config = threading.RLock()
        self.pyas_config = {}
        self.save_config = Mock(return_value=True)

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

    def test_save_failure_rolls_back(self):
        request = self.request()
        self.owner.pyas_config['alert_allow_rules'] = []
        self.owner.save_config.return_value = False
        self.assertFalse(self.owner._remember_alert_decision(request, 'permanent'))
        self.assertEqual(self.owner.pyas_config['alert_allow_rules'], [])

    def test_repeat_off_by_default_and_fixed_expiry_use_limit(self):
        request = self.request()
        self.assertTrue(self.owner._remember_alert_decision(request, 'allow'))
        self.assertIsNone(self.owner._lookup_alert_decision(request.rule))
        with patch('PYAS_Decisions.time.monotonic', return_value=100):
            self.assertTrue(self.owner._remember_alert_decision(request, 'allow', repeat=True))
        with patch('PYAS_Decisions.time.monotonic', return_value=110):
            for _ in range(20):
                self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'allow')
            self.assertIsNone(self.owner._lookup_alert_decision(request.rule))
        with patch('PYAS_Decisions.time.monotonic', return_value=200):
            self.owner._remember_alert_decision(request, 'block', repeat=True)
        with patch('PYAS_Decisions.time.monotonic', return_value=229):
            self.assertIsNone(self.owner._lookup_alert_decision(request.rule, uses=21))
            self.assertEqual(self.owner._lookup_alert_decision(request.rule), 'block')
        with patch('PYAS_Decisions.time.monotonic', return_value=230):
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
