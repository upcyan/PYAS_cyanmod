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
