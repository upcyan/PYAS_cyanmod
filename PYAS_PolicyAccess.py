"""Fork-owned preflight guards; upstream engines/drivers are not rewritten."""
import copy
import hashlib
import json
import os
import threading
from PYAS_Policy import (POLICY_KEYS, USER_KEYS, PolicyDenied, bounded_json, policy_values,
                         white_list_identity)


def _append_missing_white_list(candidate, defaults):
    """把默认白名单并入候选策略,同一路径只留一条。

    默认项是 {file, is_dir, time: 0}:整串比较时它和用户那条(带时间戳)不相等,
    迁移/初始化各并一次,白名单页就会出现两条同路径、一条没有日期。
    """
    existing = {white_list_identity(item) for item in candidate.get('white_list', [])}
    for item in defaults:
        key = white_list_identity(item)
        if key and key in existing:
            continue
        candidate.setdefault('white_list', []).append(copy.deepcopy(item))
        if key:
            existing.add(key)

class PolicyAccessMixin:
    def _load_scoped_config(self):
        import atexit
        from PYAS_Policy import PolicyStore
        from PYAS_PolicyWindows import WindowsPolicyBackend
        defaults = copy.deepcopy(self.pyas_default)
        defaults['language'] = self.detect_system_language()
        # Preserve the fork's explicit self-component entries without a startup
        # policy mutation or an unsolicited UAC prompt.
        own_files = [getattr(self, 'file_pyas', '')]
        if getattr(self, 'path_pyas', ''):
            own_files.append(os.path.join(self.path_pyas, 'PYAS_Menu.exe'))
        for path in own_files:
            if path and os.path.isfile(path):
                path = os.path.abspath(path)
                # 按路径比较(大小写不敏感),否则同一文件会被当成两条
                if not any(white_list_identity(item) == white_list_identity(path)
                           for item in defaults.get('white_list', [])):
                    defaults.setdefault('white_list', []).append({'file': path, 'is_dir': False, 'time': 0})
        try:
            factory = getattr(self, '_policy_backend_factory', WindowsPolicyBackend)
            backend = factory(self)
            store = PolicyStore(defaults, backend)
            self._policy_store = store
            self.pyas_config = store.load()
            self.file_config = backend.policy_file
            atexit.register(store.close)
        except Exception as error:
            # Never fall back to the old globally writable configuration.
            self._policy_store = None
            self._policy_error = str(error)
            self.pyas_config = defaults
            from PYAS_Policy import BOOL_KEYS
            for key in BOOL_KEYS:
                self.pyas_config[key] = False
            self._policy_notice('Protected policy is unavailable')

    def init_whitelist(self):
        if not getattr(self, '_policy_required', False):
            return super().init_whitelist()
        from PYAS_ComponentTrust import component_digest
        self._menu_component_digest = component_digest(os.path.join(self.path_pyas, 'PYAS_Menu.exe'))
        # Self paths were part of the reviewed default/import proposal. Never
        # silently rewrite an administrator's whitelist during engine startup.

    def get_config(self):
        result = super().get_config()
        result['policy_status'] = self.get_policy_status()
        return result

    def _policy_call(self, scope, callback, failure=False, operation='change', initialize=False):
        store = getattr(self, '_policy_store', None)
        if store is None:
            return failure if getattr(self, '_policy_required', False) else callback()
        existing = getattr(store.local, 'lease', None)
        scope = frozenset(scope)
        if existing:
            if not scope.issubset(existing.scope): return failure
            previous_user_only = getattr(store.local, 'user_only', False)
            store.local.user_only = False
            try: return callback()
            finally: store.local.user_only = previous_user_only
        try:
            lease = store.begin(scope, operation, initialize)
        except (PolicyDenied, OSError, ValueError) as error:
            self._policy_notice(str(error))
            return failure
        previous_user_only = getattr(store.local, 'user_only', False)
        store.local.user_only = False
        try:
            if getattr(self, 'closing', False): return failure
            return callback()
        finally:
            store.local.user_only = previous_user_only
            store.finish(lease)

    def _policy_notice(self, message):
        if hasattr(self, 'write_log'):
            self.write_log('WARN', 'Policy Authorization', detail=str(message)[:300], success=False)

    def _user_data_call(self, callback):
        store = getattr(self, '_policy_store', None)
        if store is None: return callback()
        previous = getattr(store.local, 'user_only', False)
        store.local.user_only = True
        try: return callback()
        finally: store.local.user_only = previous

    def record_ai_token_usage(self, model, tokens, requests=1):
        target = super().record_ai_token_usage
        return self._user_data_call(lambda: target(model, tokens, requests))

    def reset_ai_token_usage(self, model=None):
        target = super().reset_ai_token_usage
        return self._user_data_call(lambda: target(model))

    def update_config(self, key, value):
        target = super().update_config
        if key in USER_KEYS:
            return self._user_data_call(lambda: target(key, value))
        if key not in POLICY_KEYS:
            self._policy_notice('Unknown configuration field')
            return self.pyas_config.get(key)
        # Coupled menu fallback is still part of this explicit authorization.
        scope = {'context_switch', 'classic_menu_switch'} if key in ('context_switch', 'classic_menu_switch') else {key}
        def update():
            result = target(key, value)
            # A runtime failure may already have the requested value while its
            # desired machine policy differs; persist only that authorized scope.
            if self.pyas_config.get(key) == value:
                if not self.save_config(): return self.pyas_config.get(key)
            return result
        return self._policy_call(scope, update, self.pyas_config.get(key), 'setting:' + key)

    def reset_config(self):
        target = super().reset_config
        return self._policy_call(POLICY_KEYS, target, False, 'reset')

    def save_ai_config(self, base_url=None, model=None, provider_mode=None, api_key=None):
        target = super().save_ai_config
        return self._policy_call({'ai_base_url', 'ai_model', 'ai_provider_mode', 'ai_api_key', 'ai_api_key_enc'},
            lambda: target(base_url, model, provider_mode, api_key),
            {'ok': False, 'error': 'administrator_authorization_required'}, 'ai-model')

    def manage_named_list(self, list_key, files, action='add', lock_func=None):
        target = super().manage_named_list
        if list_key == 'quarantine':
            # In-place quarantine session data never creates an allow rule.
            return self._user_data_call(lambda: target(list_key, files, action, lock_func))
        if list_key not in ('white_list', 'block_list', 'custom_rule'): return 0
        return self._policy_call({list_key}, lambda: target(list_key, files, action, lock_func), 0, 'list:' + list_key)

    def remove_list_items(self, list_key, paths_to_remove):
        target = super().remove_list_items
        if list_key == 'quarantine': return self._user_data_call(lambda: target(list_key, paths_to_remove))
        if list_key not in ('white_list', 'block_list', 'custom_rule'): return False
        # Realtime quarantine checks this path even when no whitelist entry exists.
        if list_key == 'white_list':
            requested = self.norm_path(paths_to_remove or [], must_exist=False)
            if isinstance(requested, str): requested = [requested]
            normalized = {os.path.normcase(p) for p in requested if p}
            with self.lock_config:
                entries = list(self.pyas_config.get('white_list', []))
            if not any(os.path.normcase(str(x.get('file', '') if isinstance(x, dict) else x)) in normalized for x in entries):
                return False
        return self._policy_call({list_key}, lambda: target(list_key, paths_to_remove), False, 'remove:' + list_key)

    def add_popup_rule(self, rule):
        target = super().add_popup_rule
        return self._policy_call({'block_list'}, lambda: target(rule), False, 'popup-rule')

    def remove_popup_rules(self, identifiers):
        target = super().remove_popup_rules
        return self._policy_call({'block_list'}, lambda: target(identifiers), False, 'remove-popup-rule')

    def _remember_alert_decisions(self, requests, choice, repeat=False):
        """合并告警的一次裁决:永久允许只弹一次 UAC,里面把每条规则都写掉。"""
        items = [item for item in requests if getattr(item, 'rule', None)]

        if not items:
            return False

        if choice != 'permanent':
            return super()._remember_alert_decisions(items, choice, repeat)

        target = super()._remember_alert_decisions
        return self._policy_call({'alert_allow_rules'}, lambda: target(items, choice, repeat),
                                 False, 'permanent-allow')

    def _remember_suppression(self, request, reason, note, scope):
        target = super()._remember_suppression
        return self._policy_call({'suppress_rules'}, lambda: target(request, reason, note, scope), False, 'false-positive')

    def _remember_alert_decision(self, request, choice, repeat=False):
        target = super()._remember_alert_decision
        if choice != 'permanent': return target(request, choice, repeat)
        return self._policy_call({'alert_allow_rules'}, lambda: target(request, choice, repeat), False, 'permanent-allow')

    def delete_release_record(self, kind, ident):
        target = super().delete_release_record
        field = {'permanent': 'alert_allow_rules', 'suppress': 'suppress_rules'}.get(kind)
        if not field: return False
        return self._policy_call({field}, lambda: target(kind, ident), False, 'remove-release')

    def clear_release_records(self, kind=None):
        target = super().clear_release_records
        return self._policy_call({'alert_allow_rules', 'suppress_rules'}, lambda: target(kind), False, 'clear-releases')

    def clear_alert_decisions(self):
        target = super().clear_alert_decisions
        return self._policy_call({'alert_allow_rules'}, target, False, 'clear-permanent')

    def delete_suppression_rule(self, rule_id):
        target = super().delete_suppression_rule
        return self._policy_call({'suppress_rules'}, lambda: target(rule_id), False, 'remove-false-positive')

    def resolve_ai_rule_draft(self, draft_id, approve):
        target = super().resolve_ai_rule_draft
        if not approve: return self._user_data_call(lambda: target(draft_id, approve))
        return self._policy_call({'suppress_rules'}, lambda: target(draft_id, approve), False, 'approve-ai-draft')

    def generate_ai_rule_drafts(self):
        target = super().generate_ai_rule_drafts
        return self._user_data_call(target)

    def get_policy_status(self):
        store = getattr(self, '_policy_store', None)
        if not store: return {'state': 'unavailable', 'initialized': False}
        status = store.snapshot()
        # Preview is explicit and outside config/queue locks; do not read an
        # untrusted legacy file on every status poll.
        status['legacy_available'] = True
        return status

    def _legacy_policy_candidate(self):
        store = getattr(self, '_policy_store', None)
        if not store: return None
        try:
            raw = store.backend.read_legacy()
            if len(raw) > 2 * 1024 * 1024: return None
            data = json.loads(raw.decode('utf-8-sig'))
            if not isinstance(data, dict): return None
            candidate = {key: copy.deepcopy(value) for key, value in data.items() if key in POLICY_KEYS}
            # Legacy plaintext credentials are converted in the original user's token.
            if candidate.get('ai_api_key'):
                from PYAS_AI import protect_ai_key
                candidate['ai_api_key_enc'] = protect_ai_key(str(candidate['ai_api_key']))
                candidate['ai_api_key'] = ''
            policy_values(candidate)
            user_data = {key: copy.deepcopy(value) for key, value in data.items() if key in USER_KEYS}
            return candidate, hashlib.sha256(raw).hexdigest(), user_data
        except (OSError, ValueError, TypeError): return None

    def get_policy_defaults_preview(self):
        store = getattr(self, '_policy_store', None)
        if store is None: return {'available': False}
        values = policy_values(store.defaults)
        for key in ('api_key', 'ai_api_key', 'ai_api_key_enc'):
            if values.get(key): values[key] = '[redacted]'
        return {'available': True, 'values': values}

    def get_policy_migration_preview(self):
        source = self._legacy_policy_candidate()
        if source is None: return {'available': False}
        candidate, digest, user_data = source
        candidate = {**policy_values(self._policy_store.defaults), **candidate}
        _append_missing_white_list(candidate, self._policy_store.defaults.get('white_list', []))
        safe = copy.deepcopy(candidate)
        for key in ('api_key', 'ai_api_key', 'ai_api_key_enc'):
            if safe.get(key): safe[key] = '[redacted]'
        return {'available': True, 'digest': digest, 'values': {'security_policy': safe, 'user_data': user_data}}

    def initialize_security_policy(self, import_legacy=False, digest=None):
        store = getattr(self, '_policy_store', None)
        if store is None or store.revision is not None:
            return {'ok': False, 'error': 'already_initialized_or_unavailable'}
        candidate = copy.deepcopy(store.defaults)
        user_data = {}
        if import_legacy:
            source = self._legacy_policy_candidate()
            if source is None or source[1] != digest:
                return {'ok': False, 'error': 'legacy_configuration_changed'}
            candidate.update(source[0])
            user_data = source[2]
            _append_missing_white_list(candidate, store.defaults.get('white_list', []))
        values = policy_values(candidate)
        def initialize():
            with self.lock_config:
                previous = copy.deepcopy(self.pyas_config)
                self.pyas_config.update(values)
                self.pyas_config.update(user_data)
                try:
                    ok = self.save_config()
                finally:
                    # Do not display unstarted protections as active. Restart
                    # loads approved desired settings through the existing engine.
                    for key in POLICY_KEYS:
                        if key in previous: self.pyas_config[key] = previous[key]
                        else: self.pyas_config.pop(key, None)
            if ok:
                store.status = {'state': 'restart_required', 'error': ''}
                return {'ok': True, 'restart_required': True}
            return {'ok': False, 'error': 'policy_commit_failed'}
        result = self._policy_call(POLICY_KEYS, initialize,
            {'ok': False, 'error': 'administrator_authorization_required'}, 'initialize', initialize=True)
        if not result.get('ok'):
            status = store.snapshot()
            result = {**result, 'state': status['state'], 'detail': status.get('error', ''),
                      'cancelled': status.get('cancelled', False)}
            if result['detail'] and result['error'] == 'policy_commit_failed':
                self._policy_notice(result['detail'])
        return result
