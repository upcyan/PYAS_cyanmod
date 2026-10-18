"""R1 entry guards: cancellation before effects and no config lock during UAC."""
import copy
import threading
import tempfile
import unittest
from unittest.mock import Mock
from PYAS_Config import ConfigMixin
from PYAS_Policy import PolicyStore, POLICY_KEYS
from PYAS_PolicyAccess import PolicyAccessMixin
from test_policy_store import Backend

class Owner(PolicyAccessMixin, ConfigMixin):
    def __init__(self, backend):
        self._policy_required = True
        self.lock_config, self.lock_update = threading.RLock(), threading.RLock()
        self.pyas_default = {'version':'test', 'language':'english_switch', 'theme':'system_switch',
            'first_launch':False, 'process_switch':True, 'white_list':[], 'ai_api_key':''}
        self.write_log = Mock(); self.tray_icon = None; self._window = None
        self.path_rules = 'not-a-directory'
        self.autostart_mode = 'disabled'
        self.effects = []
        self.protect_proc_thread = lambda: None
        self.protect_file_thread = lambda: None
        self.protect_system_thread = lambda: None
        self.protect_net_thread = lambda: None
        self.start_feature_thread = lambda *args: self.effects.append('started')
        self._policy_backend_factory = lambda owner: backend
        self.detect_system_language = lambda: 'english_switch'
        self.load_config()

class AccessBackend(Backend):
    policy_file = 'protected-policy-placeholder'
    legacy_file = 'missing-legacy-placeholder'

class PolicyAccessTests(unittest.TestCase):
    def setUp(self): self.backend = AccessBackend(); self.owner = Owner(self.backend)
    def initialize(self):
        self.assertTrue(self.owner.initialize_security_policy()['ok'])
        self.owner.load_config()  # simulate normal restart, never auto-run an engine
        self.backend.prompts = 0
    def test_missing_policy_ignores_legacy_security_and_does_not_start_features(self):
        self.assertFalse(self.owner.pyas_config['process_switch'])
        self.assertEqual(self.owner.effects, [])
        self.assertEqual(self.owner.file_config, self.backend.policy_file)
        self.assertEqual(self.owner.get_config()['policy_status']['state'], 'not_initialized')
    def test_user_preferences_save_before_initialization_without_uac(self):
        self.assertEqual(self.owner.update_config('theme','white_switch'), 'white_switch')
        self.assertEqual(self.backend.user['theme'], 'white_switch')
        self.assertEqual(self.backend.prompts, 0)
        self.assertIsNone(self.backend.document)
    def test_initialization_requires_explicit_authorization_and_restart(self):
        self.assertTrue(self.owner.initialize_security_policy()['ok'])
        self.assertFalse(self.owner.pyas_config['process_switch'])
        self.assertTrue(self.backend.document['process_switch'])
        self.assertEqual(self.owner.get_policy_status()['state'], 'restart_required')
        self.assertFalse(self.owner.update_config('process_switch', True))
        self.assertEqual(self.owner.effects, [])
    def test_cancelled_authorization_never_changes_memory_or_effects(self):
        self.initialize(); self.backend.allow = False
        previous = copy.deepcopy(self.backend.document)
        self.assertTrue(self.owner.update_config('process_switch', False))
        self.assertTrue(self.owner.pyas_config['process_switch'])
        self.assertEqual(self.backend.document, previous)
        self.assertEqual(self.owner.effects, [])
    def test_successful_authorization_precedes_side_effects(self):
        self.initialize()
        self.assertFalse(self.owner.update_config('process_switch', False))
        self.assertFalse(self.backend.document['process_switch'])
        self.assertTrue(self.owner.update_config('process_switch', True))
        self.assertEqual(self.owner.effects, ['started'])
    def test_config_lock_and_user_preferences_remain_available_during_uac(self):
        self.initialize()
        entered, release = threading.Event(), threading.Event()
        original = self.backend.authorize
        def authorize(*args):
            self.assertTrue(self.owner.pyas_config['process_switch'])
            entered.set(); release.wait(2)
            return original(*args)
        self.backend.authorize = authorize
        worker = threading.Thread(target=lambda: self.owner.update_config('process_switch', False))
        try:
            worker.start(); self.assertTrue(entered.wait(1))
            acquired = self.owner.lock_config.acquire(timeout=.2)
            self.assertTrue(acquired)
            if acquired: self.owner.lock_config.release()
            self.assertEqual(self.owner.update_config('theme','black_switch'),'black_switch')
        finally: release.set(); worker.join(2)
        self.assertEqual(self.backend.user['theme'], 'black_switch')
    def test_unknown_field_cannot_change_runtime_or_storage(self):
        self.initialize()
        self.assertIsNone(self.owner.update_config('unapproved_security_field', True))
        self.assertNotIn('unapproved_security_field', self.owner.pyas_config)
        self.assertNotIn('unapproved_security_field', self.backend.document)
    def test_reviewed_migration_preserves_user_data_without_promoting_it_to_policy(self):
        import json
        raw = json.dumps({'process_switch':True, 'theme':'black_switch',
            'quarantine':[{'file':'C:/fixture/blocked.exe','time':1}], 'unknown_field':True}).encode()
        self.backend.read_legacy = lambda: raw
        preview = self.owner.get_policy_migration_preview()
        self.assertTrue(preview['available'])
        self.assertIn('quarantine', preview['values']['user_data'])
        self.backend.allow = False
        self.assertFalse(self.owner.initialize_security_policy(True, preview['digest'])['ok'])
        self.assertNotIn('quarantine', self.backend.user)
        self.backend.allow = True
        self.assertTrue(self.owner.initialize_security_policy(True, preview['digest'])['ok'])
        self.assertEqual(self.backend.user['theme'], 'black_switch')
        self.assertEqual(self.backend.user['quarantine'][0]['file'], 'C:/fixture/blocked.exe')
        self.assertNotIn('quarantine', self.backend.document)
        self.assertNotIn('unknown_field', self.backend.document)
        self.assertFalse(self.owner.pyas_config['process_switch'])

    def test_changed_legacy_snapshot_never_opens_authorization(self):
        self.backend.read_legacy = lambda: b'{"process_switch":true}'
        result = self.owner.initialize_security_policy(True, 'wrong')
        self.assertFalse(result['ok'])
        self.assertEqual(self.backend.prompts,0)

    def test_required_store_never_falls_back_to_globally_writable_file(self):
        with tempfile.TemporaryDirectory() as directory:
            self.owner._policy_store = None
            self.owner.file_config = directory + '/Config.json'
            self.assertFalse(self.owner.save_config())
            self.assertFalse(self.owner.update_config('process_switch', True))
    def test_commit_wait_releases_recursive_configuration_lock(self):
        from PYAS_PolicyWindows import WindowsPolicyBackend
        backend = object.__new__(WindowsPolicyBackend); backend.owner = self.owner
        entered = threading.Event()
        errors = []
        def wait():
            try:
                with self.owner.lock_config:
                    with self.owner.lock_config:
                        entered.set(); backend.pause(.3)
                        self.assertTrue(self.owner.lock_config._is_owned())
            except BaseException as error: errors.append(error)
        worker = threading.Thread(target=wait)
        try:
            worker.start(); self.assertTrue(entered.wait(1))
            acquired = self.owner.lock_config.acquire(timeout=.2)
            self.assertTrue(acquired)
            if acquired: self.owner.lock_config.release()
        finally: worker.join(2)
        self.assertEqual(errors, [])

if __name__ == '__main__': unittest.main()
