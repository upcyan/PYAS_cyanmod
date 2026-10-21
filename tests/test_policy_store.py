"""Administrator policy versus user data; no Windows or UAC side effects."""
import copy
import threading
import unittest
from PYAS_Policy import FORMAT, PolicyStore, PolicyDenied, POLICY_KEYS

class Lease:
    def __init__(self, backend, scope, revision, authorized=True):
        self.backend, self.scope, self.revision = backend, scope, revision
        self.authorized, self.closed = authorized, False
    def commit(self, updates):
        current = self.backend.document
        if (current or {}).get('_revision') != self.revision: raise PolicyDenied('conflict')
        self.backend.document = {**(current or {}), **copy.deepcopy(updates), '_format': FORMAT, '_revision': 'new'}
        return copy.deepcopy(self.backend.document)
    def close(self): self.closed = True

class Backend:
    def __init__(self): self.user, self.document, self.allow, self.prompts = {}, None, True, 0
    def read_user(self): return copy.deepcopy(self.user)
    def read_policy(self): return copy.deepcopy(self.document)
    def write_user(self, value): self.user = copy.deepcopy(value)
    def authorize(self, scope, revision, operation, initialize):
        self.prompts += 1
        return Lease(self, scope, revision, self.allow)
    def cancel(self): pass

class PolicyStoreTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.defaults = {'version': 'test', 'theme': 'system_switch', 'language': 'english_switch',
            'process_switch': False, 'white_list': [], 'suppress_rules': [], 'ai_api_key': ''}
        self.store = PolicyStore(self.defaults, self.backend)
        self.config = self.store.load()
    def initialize(self):
        lease = self.store.begin(POLICY_KEYS, initialize=True)
        try: self.assertTrue(self.store.save(self.config))
        finally: self.store.finish(lease)
    def test_corrupt_policy_fails_closed_without_losing_user_preferences(self):
        self.backend.user = {'theme':'white_switch'}
        self.backend.document = {'_format':FORMAT, '_revision':'old', 'process_switch':'not a boolean'}
        config = self.store.load()
        self.assertFalse(config['process_switch'])
        self.assertEqual(config['theme'],'white_switch')
        self.assertIsNone(self.store.revision)
        self.assertEqual(self.store.snapshot()['state'],'not_initialized')
        self.assertIn('invalid',self.store.snapshot()['error'])

    def test_user_data_cannot_override_security_fields(self):
        self.backend.user = {'theme': 'white_switch', 'process_switch': True, 'white_list': [{'file':'unsafe'}]}
        config = self.store.load()
        self.assertEqual(config['theme'], 'white_switch')
        self.assertFalse(config['process_switch'])
        self.assertEqual(config['white_list'], [])
    def test_preferences_and_usage_do_not_prompt(self):
        self.config.update(theme='white_switch', ai_token_usage={'model': {'tokens': 5}})
        self.assertTrue(self.store.save(self.config))
        self.assertEqual(self.backend.prompts, 0)
        self.assertIsNone(self.backend.document)
    def test_uninitialized_policy_cannot_be_changed_implicitly(self):
        with self.assertRaises(PolicyDenied): self.store.begin({'process_switch'})
        self.assertEqual(self.backend.prompts, 0)
    def test_denied_authorization_cannot_publish_or_persist(self):
        self.initialize(); self.backend.allow = False
        before = copy.deepcopy(self.backend.document)
        with self.assertRaises(PolicyDenied): self.store.begin({'process_switch'})
        self.assertEqual(self.backend.document, before)
        self.assertFalse(self.store.effective()['process_switch'])
    def test_only_authorized_scope_is_committed(self):
        self.initialize()
        lease = self.store.begin({'process_switch'})
        try:
            candidate = {**self.config, 'process_switch': True, 'white_list': [{'file': 'unapproved'}]}
            self.assertTrue(self.store.save(candidate))
        finally: self.store.finish(lease)
        self.assertTrue(self.store.values['process_switch'])
        self.assertEqual(self.store.values['white_list'], [])
    def test_no_lease_cannot_write_security_or_unknown_fields(self):
        self.initialize()
        self.assertFalse(self.store.save({**self.config, 'process_switch': True}))
        self.assertFalse(self.store.save({**self.config, 'new_privileged_flag': True}))
        # 拒绝写入即可,但状态不能被这类后台写入打成错误:
        # 面板会把 status.error 直接显给用户,一句「需要管理员授权」会把整块设置变成红条
        self.assertEqual(self.store.status.get('error'), '')
    def test_conflict_is_not_retried_or_overwritten(self):
        self.initialize(); lease = self.store.begin({'process_switch'})
        self.backend.document['_revision'] = 'different'
        try: self.assertFalse(self.store.save({**self.config, 'process_switch': True}))
        finally: self.store.finish(lease)
        self.assertEqual(self.backend.document['_revision'], 'different')
        self.assertFalse(self.store.values['process_switch'])
    def test_runtime_counters_are_not_policy_grants(self):
        self.config['alert_allow_rules'] = [{'key':'x','sha256':'a'*64,'hits':0}]
        self.initialize()
        self.config['alert_allow_rules'][0]['hits'] = 51
        self.assertTrue(self.store.save(self.config))
        self.assertNotIn('hits', self.backend.document['alert_allow_rules'][0])
        self.backend.user['_rule_counters'].clear()
        self.assertEqual(self.store.load()['alert_allow_rules'][0]['hits'], 0)
    def test_concurrent_authorizations_are_rejected_without_second_prompt(self):
        self.initialize(); lease = self.store.begin({'process_switch'})
        try:
            with self.assertRaises(PolicyDenied): self.store.begin({'white_list'})
        finally: self.store.finish(lease)
        self.assertEqual(self.backend.prompts, 2)

if __name__ == '__main__': unittest.main()


class WhiteListDedupeTests(unittest.TestCase):
    """同一路径只该有一条;默认项(time=0)不能让位成第二条(2026-10-19 白名单重复)。"""

    def _store(self, white_list):
        backend = Backend()
        backend.document = {'white_list': white_list, '_format': FORMAT, '_revision': 'r1'}
        return PolicyStore({}, backend)

    def test_placeholder_yields_to_the_timed_entry(self):
        path = r'C://Program Files\PYAS\PYAS.exe'
        store = self._store([
            {'file': path, 'is_dir': False, 'time': 1791418961.19},
            {'file': path, 'is_dir': False, 'time': 0},
        ])
        values = store.load()['white_list']
        self.assertEqual(len(values), 1)
        self.assertGreater(values[0].get("time", 0), 0)

    def test_case_and_trailing_separator_do_not_create_duplicates(self):
        store = self._store([
            {'file': r'C://Program Files\PYAS\PYAS.exe', 'is_dir': False, 'time': 1.0},
            {'file': r'c://program files\pyas\pyas.exe', 'is_dir': False, 'time': 0},
            {'file': r'C://Program Files\PYAS\PYAS_Menu.exe', 'is_dir': False, 'time': 2.0},
        ])
        values = store.load()['white_list']
        self.assertEqual(len(values), 2)

    def test_distinct_paths_are_kept(self):
        store = self._store([
            {'file': r'C://a.exe', 'is_dir': False, 'time': 1.0},
            {'file': r'C://b.exe', 'is_dir': False, 'time': 2.0},
        ])
        self.assertEqual(len(store.load()['white_list']), 2)


class MergeDefaultsTests(unittest.TestCase):
    """迁移/初始化把默认自组件并进候选策略时,不能与已有路径并存。"""

    def test_existing_path_is_not_appended_again(self):
        from PYAS_PolicyAccess import _append_missing_white_list
        candidate = {'white_list': [{'file': r'C://Program Files\PYAS\PYAS.exe', 'is_dir': False, 'time': 5.0}]}
        defaults = [{'file': r'c://program files\pyas\pyas.exe', 'is_dir': False, 'time': 0}]
        _append_missing_white_list(candidate, defaults)
        self.assertEqual(len(candidate['white_list']), 1)

    def test_missing_path_is_still_added(self):
        from PYAS_PolicyAccess import _append_missing_white_list
        candidate = {'white_list': [{'file': r'C://a.exe', 'is_dir': False, 'time': 5.0}]}
        defaults = [{'file': r'C://Program Files\PYAS\PYAS.exe', 'is_dir': False, 'time': 0}]
        _append_missing_white_list(candidate, defaults)
        self.assertEqual(len(candidate['white_list']), 2)


if __name__ == "__main__":
    unittest.main()
