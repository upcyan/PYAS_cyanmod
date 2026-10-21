"""Fork policy boundary: administrator policy, user preferences and runtime data.

No UI or Windows imports: transactional behavior can be tested independently.
"""
import copy
import hashlib
import json
import logging
import math
import os
import threading
import time

USER_KEYS = frozenset({'language', 'theme', 'first_launch', 'driver_alert_exempt',
    'driver_home_hidden',
    'notify_channel', 'dnd_switch', 'ai_token_usage', 'ai_rule_drafts', 'ai_guide_seen',
    'quarantine'})
BOOL_KEYS = frozenset({'process_switch', 'suspend_switch', 'load_switch', 'document_switch',
    'system_switch', 'driver_switch', 'network_switch', 'extension_switch', 'sensitive_switch',
    'cloud_switch', 'suffix_switch', 'autostart_switch', 'context_switch', 'interactive_switch',
    'interactive_auto_block', 'classic_menu_switch', 'agent_switch', 'ai_assist_switch',
    'ai_auto_execute', 'ai_delay_switch'})
STRING_KEYS = frozenset({'api_host', 'api_key', 'ai_provider_mode', 'ai_base_url',
    'ai_api_key', 'ai_api_key_enc', 'ai_model'})
NUMBER_KEYS = frozenset({'size', 'interactive_timeout', 'ai_auto_execute_timeout', 'ai_delay_seconds'})
LIST_KEYS = frozenset({'suffix', 'custom_rule', 'white_list', 'block_list', 'suppress_rules', 'alert_allow_rules'})
POLICY_KEYS = BOOL_KEYS | STRING_KEYS | NUMBER_KEYS | LIST_KEYS
MAX_BYTES = 2 * 1024 * 1024
FORMAT = 'pyas-admin-policy-v1'


class PolicyDenied(RuntimeError): pass
class PolicyCancelled(PolicyDenied): pass
class PolicyConflict(PolicyDenied): pass
class PolicyPending(PolicyDenied): pass


def bounded_json(data):
    raw = json.dumps(data, ensure_ascii=False, allow_nan=False, sort_keys=True,
                     separators=(',', ':')).encode('utf-8')
    if len(raw) > MAX_BYTES:
        raise ValueError('Policy document is too large')
    return raw


def white_list_identity(item):
    """白名单条目的去重键:同一个文件路径,大小写与分隔符无关。"""
    value = item.get('file') if isinstance(item, dict) else item
    if not isinstance(value, str) or not value.strip():
        return ''
    return os.path.normcase(value.strip().rstrip('\\'))


def dedupe_white_list(items):
    """同一路径只保留一条,优先带真实时间戳的那条。

    默认策略里的自身组件是 {file, is_dir, time: 0}(没有日期),迁移/初始化时
    按整串比较会把它和用户那条并存,白名单页就出现两条同路径、一条日期为空的记录。
    """
    result = []
    index = {}
    for item in items or []:
        key = white_list_identity(item)
        if not key:
            result.append(item)
            continue
        if key not in index:
            index[key] = len(result)
            result.append(item)
            continue
        previous = result[index[key]]
        if isinstance(previous, dict) and isinstance(item, dict):
            # 占位项(time=0)让位给真正记录过时间的条目
            if not previous.get('time') and item.get('time'):
                result[index[key]] = item
    return result

def validate_values(values):
    if not isinstance(values, dict) or set(values) - POLICY_KEYS:
        raise ValueError('Unknown policy field')
    bounded_json(values)
    for key, value in values.items():
        if key in BOOL_KEYS and not isinstance(value, bool):
            raise ValueError('Policy switch requires a boolean')
        if key in STRING_KEYS and (not isinstance(value, str) or len(value) > 32768):
            raise ValueError('Invalid policy string')
        if key in NUMBER_KEYS and value is not None and (isinstance(value, bool)
                or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 or value > 2**63 - 1):
            raise ValueError('Invalid policy number')
        if key in LIST_KEYS and (not isinstance(value, list) or len(value) > 4096):
            raise ValueError('Invalid policy list')
    if values.get('ai_api_key'):
        raise ValueError('AI credentials must use encrypted storage')
    return copy.deepcopy(values)


def policy_values(config, now=None):
    values = {key: copy.deepcopy(value) for key, value in config.items() if key in POLICY_KEYS}
    for key in ('alert_allow_rules', 'suppress_rules'):
        if key not in values:
            continue
        cleaned = []
        for item in values[key]:
            if not isinstance(item, dict):
                continue
            item = dict(item)
            item.pop('hits', None); item.pop('last_hit', None)
            # Expiry is an administrator-approved restriction, not a new grant.
            if key == 'suppress_rules' and isinstance(item.get('expires'), (int, float)):
                if item['expires'] <= (time.time() if now is None else now):
                    continue
            cleaned.append(item)
        values[key] = cleaned
    return validate_values(values)


def counter_key(item):
    definition = {key: value for key, value in item.items() if key not in ('hits', 'last_hit')}
    return hashlib.sha256(bounded_json(definition)).hexdigest()


class PolicyStore:
    """One-shot authorization precedes effects; save never silently elevates."""
    def __init__(self, defaults, backend):
        self.defaults = copy.deepcopy(defaults)
        for key in BOOL_KEYS: self.defaults.setdefault(key, False)
        for key in STRING_KEYS: self.defaults.setdefault(key, '')
        for key in NUMBER_KEYS: self.defaults.setdefault(key, 0)
        for key in LIST_KEYS: self.defaults.setdefault(key, [])
        self.defaults.setdefault('alert_allow_rules', [])
        self.defaults.setdefault('ai_api_key_enc', '')
        self.backend = backend
        self.lock = threading.RLock()
        self.operation = threading.Lock()
        self.local = threading.local()
        self.values = policy_values(self.defaults)
        self.revision = None
        self.status = {'state': 'not_initialized', 'error': ''}
        self.user = {}
        self.cancelled = False

    def load(self):
        with self.lock:
            try:
                user = self.backend.read_user()
            except (OSError, ValueError):
                user = {}
            self.user = user if isinstance(user, dict) else {}
            self.values = policy_values(self.defaults)
            self.revision = None
            self.status = {'state': 'not_initialized', 'error': ''}
            try:
                document = self.backend.read_policy()
                if document and document.get('_format') == FORMAT:
                    values = {key: value for key, value in document.items() if key in POLICY_KEYS}
                    validate_values(values)
                    revision = str(document.get('_revision') or '')
                    if not revision: raise ValueError('Missing policy revision')
                    self.values.update(values)
                    # 历史数据里可能已经并存了 time=0 的默认项,读入时按路径合并掉
                    self.values['white_list'] = dedupe_white_list(self.values.get('white_list', []))
                    self.revision = revision
                    self.status = {'state': 'ready', 'error': ''}
            except (OSError, ValueError, TypeError):
                self.status = {'state': 'not_initialized', 'error': 'Protected policy is invalid; administrator initialization is required'}
            return self.effective()

    def effective(self):
        result = copy.deepcopy(self.defaults)
        result.update(copy.deepcopy(self.values))
        if self.revision is None:
            # No unreviewed legacy grants or startup side effects.
            for key in BOOL_KEYS: result[key] = False
        for key in USER_KEYS:
            if key in self.user:
                result[key] = copy.deepcopy(self.user[key])
        counters = self.user.get('_rule_counters', {})
        if isinstance(counters, dict):
            for key in ('alert_allow_rules', 'suppress_rules'):
                for item in result.get(key, []):
                    if not isinstance(item, dict): continue
                    metadata = counters.get(counter_key(item), {})
                    if isinstance(metadata, dict):
                        try: item['hits'] = max(0, min(2**53 - 1, int(metadata.get('hits') or 0)))
                        except (ValueError, TypeError, OverflowError): item['hits'] = 0
                        if isinstance(metadata.get('last_hit'), (int, float)):
                            item['last_hit'] = max(0, metadata['last_hit'])
        return result

    def begin(self, scope, operation='change', initialize=False):
        scope = frozenset(scope)
        if not scope or scope - POLICY_KEYS:
            raise PolicyDenied('Unsupported policy operation')
        if self.cancelled:
            raise PolicyDenied('Application is closing')
        if self.status.get('state') in ('restart_required', 'commit_unknown'):
            raise PolicyDenied('Restart the application before changing more security settings')
        if not self.operation.acquire(blocking=False):
            raise PolicyDenied('Another policy authorization is in progress')
        try:
            if self.revision is None and not initialize:
                raise PolicyDenied('Initialize administrator policy first')
            self.status = {'state': 'authorizing', 'error': ''}
            lease = self.backend.authorize(scope, self.revision, operation, initialize)
            if not lease or not lease.authorized or self.cancelled:
                if lease: lease.close()
                raise PolicyDenied('Administrator authorization was cancelled')
            self.local.lease = lease
            self.status = {'state': 'applying', 'error': ''}
            return lease
        except Exception as error:
            self.status = {'state': 'ready' if self.revision else 'not_initialized', 'error': str(error),
                           'cancelled': isinstance(error, PolicyCancelled)}
            self.operation.release()
            raise

    def finish(self, lease):
        try:
            lease.close()
        finally:
            self.local.lease = None
            if self.status.get('state') in ('authorizing', 'applying'):
                self.status = {'state': 'ready' if self.revision else 'not_initialized', 'error': ''}
            if self.operation.locked(): self.operation.release()

    def save(self, config):
        user = {key: copy.deepcopy(config[key]) for key in USER_KEYS if key in config}
        counters = {}
        for key in ('alert_allow_rules', 'suppress_rules'):
            for item in config.get(key, []):
                if isinstance(item, dict):
                    counters[counter_key(item)] = {field: item[field] for field in ('hits', 'last_hit') if field in item}
        user['_rule_counters'] = counters
        self.backend.write_user(user)
        self.user = user
        if getattr(self.local, 'user_only', False):
            return True
        proposed = policy_values(config)
        lease = getattr(self.local, 'lease', None)
        if not lease:
            # Ordinary writes cannot change authority, including unknown keys.
            unknown = set(config) - POLICY_KEYS - USER_KEYS - {'version'}
            current = policy_values(self.values)
            changed = sorted(key for key, value in proposed.items() if current.get(key) != value)

            if unknown or changed:
                # 拒绝写入是必须的,但**不能**把整块安全面板打成错误态:
                # 这类调用多来自后台(命中计数、白名单元数据回填、AI 用量),
                # 它们本来就不该弹授权窗;把它记进日志,面板状态交给真正的授权流程维护。
                logging.getLogger('PYAS.Policy').warning(
                    'policy write ignored without authorization: keys=%s unknown=%s',
                    changed, sorted(unknown))
                return False

            return True
        updates = {key: proposed[key] for key in lease.scope if key in proposed}
        expected = policy_values(self.values)
        if self.revision is not None and all(expected.get(k) == value for k, value in updates.items()):
            return True
        try:
            document = lease.commit(updates)
            if not document or document.get('_format') != FORMAT or not document.get('_revision'):
                raise PolicyDenied('Policy commit was not confirmed')
            values = {key: value for key, value in document.items() if key in POLICY_KEYS}
            validate_values(values)
            with self.lock:
                self.values = {**policy_values(self.defaults), **values}
                self.revision = document['_revision']
                self.status = {'state': 'ready', 'error': ''}
            return True
        except Exception as error:
            self.status = {'state': 'commit_unknown' if isinstance(error, PolicyPending) else 'commit_failed', 'error': str(error)}
            return False

    def snapshot(self):
        with self.lock:
            return {**self.status, 'initialized': self.revision is not None,
                    'revision': self.revision}

    def close(self):
        self.cancelled = True
        self.backend.cancel()
