"""Narrow, content-bound exceptions for interactive alerts, never scan exclusions."""
import hashlib
import json
import os
import time
from contextlib import contextmanager
from uuid import uuid4

MAX_RULES = 256
REPEAT_SECONDS = 60
REPEAT_USES = 100
# 阶梯式重复有效期:已消费次数越多,窗口越长(按同一份内容的重复确认递增信任)
REPEAT_TIERS = ((40, 3600), (15, 900), (5, 300))
REPEAT_MAX_LIFETIME = 86400

# 误报抑制:只锚定文件内容(SHA-256),绝不锚定目录/进程名/扩展名。
# scope 'file_rule' = 该内容 × 该检测结果(L1);'file' = 该内容 × 全部检测(L2)
SUPPRESS_TTL = 90 * 86400
SUPPRESS_SCOPES = ('file_rule', 'file')
SUPPRESS_REASONS = ('dev_tool', 'installer', 'enterprise', 'game_patch', 'other')

# 永久允许记录随命中/展示补上 hits、created 等字段,匹配只能按身份字段比对
PERMANENT_IDENTITY_FIELDS = ('action', 'source', 'target', 'sha256', 'detection', 'key')
# 命中计数首次与每 N 次落盘一次,避免高频事件反复写配置
HIT_PERSIST_EVERY = 50


def _identity_view(item):
    return {field: item.get(field) for field in PERMANENT_IDENTITY_FIELDS} if isinstance(item, dict) else None


def _repeat_window(consumed):
    """按已消费次数查阶梯窗口:消费越多,窗口越长。"""
    for floor, seconds in REPEAT_TIERS:
        if consumed >= floor:
            return seconds
    return REPEAT_SECONDS


def alert_identity(action, source, target, detection, opener=None):
    # Re-read once if NTFS publishes final write metadata after close; never
    # accept a hash paired with inconsistent file snapshots.
    for _ in range(2):
        rule = _read_alert_identity(action, source, target, detection, opener)
        if rule is not None:
            return rule
    return None


def _read_alert_identity(action, source, target, detection, opener):
    # Memory-only DLL observations cannot be identified by their on-disk file.
    if action not in ('Process Block', 'File Block', 'Deferred Scan Block', 'Network Block') or not source or not detection:
        return None
    try:
        path = os.path.normcase(os.path.realpath(source))
        with (opener(path) if opener else open(path, 'rb')) as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > 64 * 1024 * 1024:
                return None
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(65536), b''):
                digest.update(chunk)
            after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, key) != getattr(after, key) for key in fields):
            return None
        current = os.stat(path)
        # On Windows, fstat/CRT and stat may expose different ctime semantics.
        # Compare file ID, device, size and last-write time across these APIs.
        if any(getattr(after, key) != getattr(current, key) for key in fields if key != 'st_ctime_ns'):
            return None
        evidence = json.dumps(detection, sort_keys=True, ensure_ascii=False, default=str)
        rule = {'action': action, 'source': path, 'target': str(target or ''),
                'sha256': digest.hexdigest(), 'detection': evidence}
        rule['key'] = hashlib.sha256(json.dumps(rule, sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()
        return rule
    except (OSError, ValueError, TypeError):
        return None


class AlertPolicyMixin:
    @contextmanager
    def _open_alert_file(self, path):
        lock = getattr(self, 'lock_file_ops', None)
        if lock is not None:
            with lock:
                owned = next((value for key, value in getattr(self, 'virus_lock', {}).items()
                    if os.path.normcase(os.path.abspath(key)) == path), None)
                if owned:
                    fd, _ = owned
                    position = os.lseek(fd, 0, os.SEEK_CUR)
                    class LockedReader:
                        def fileno(self):
                            return fd
                        def read(self, count):
                            return os.read(fd, count)
                    try:
                        os.lseek(fd, 0, os.SEEK_SET)
                        yield LockedReader()
                    finally:
                        os.lseek(fd, position, os.SEEK_SET)
                    return
        with open(path, 'rb') as stream:
            yield stream

    def _make_alert_identity(self, action, source, target, detection):
        return alert_identity(action, source, target, detection, opener=self._open_alert_file)

    def _alert_policy_lock(self):
        # The queue is initialized under the application's shared init lock.
        return self.lock_config

    def _lookup_alert_decision(self, rule, uses=1):
        if not rule:
            return None
        with self._alert_policy_lock():
            rules = self.pyas_config.get('alert_allow_rules', [])
            if isinstance(rules, list) and self._count_permanent_hits_locked(rules, rule):
                return 'allow'
            if self._match_suppression_locked(rule) is not None:
                return 'allow'
            recent = getattr(self, '_recent_alert_decisions', {})
            now = time.monotonic()
            for key in list(recent):
                if recent[key]['until'] <= now or recent[key]['uses'] <= 0:
                    del recent[key]
            item = recent.get(rule['key'])
            if item and item['rule'] == rule and item['uses'] >= uses:
                item['uses'] -= uses
                # 阶梯顺延:消费越多窗口越长;只延长不缩短,且受绝对寿命上限约束
                created = item.get('created', now)
                item['until'] = min(
                    max(item['until'], now + _repeat_window(REPEAT_USES - item['uses'])),
                    created + REPEAT_MAX_LIFETIME,
                )
                return item['choice']
        return None

    def _count_permanent_hits_locked(self, rules, rule):
        """按身份字段命中永久允许并累计计数;首次与每 HIT_PERSIST_EVERY 次落盘一次。"""
        matched = None

        for item in rules[:MAX_RULES]:
            if isinstance(item, dict) and _identity_view(item) == rule:
                matched = item
                break

        if matched is None:
            return False

        matched['hits'] = int(matched.get('hits', 0)) + 1

        if matched['hits'] <= 1 or matched['hits'] % HIT_PERSIST_EVERY == 0:
            self.save_config()

        return True

    def _match_suppression_locked(self, rule):
        """内容锚定抑制匹配;命中即累计审计计数,过期条目顺带清理。"""
        entries = self.pyas_config.get('suppress_rules', [])

        if not isinstance(entries, list) or not entries or not rule.get('sha256'):
            return None

        now = time.time()
        changed = False
        matched = None

        for entry in entries[:MAX_RULES]:
            if not isinstance(entry, dict):
                changed = True
                continue

            if entry.get('expires', 0) <= now:
                changed = True
                continue

            if entry.get('sha256') != rule.get('sha256'):
                continue

            if entry.get('scope') == 'file' or (
                entry.get('scope') == 'file_rule' and entry.get('detection') == rule.get('detection')
            ):
                matched = entry
                break

        if matched is not None:
            matched['hits'] = int(matched.get('hits', 0)) + 1
            matched['last_hit'] = now

            # 命中计数主要留在内存,首次与每 50 次落盘一次,避免高频事件反复写配置
            if matched['hits'] <= 1 or matched['hits'] % 50 == 0:
                changed = True

            if hasattr(self, 'write_log'):
                self.write_log('INFO', 'Suppression Hit',
                    source=rule.get('source', ''),
                    detail=f"{matched.get('scope')} / {matched.get('reason')} / {rule.get('action', '')}",
                    file_hash=rule.get('sha256'))

        if changed:
            kept = [entry for entry in entries if isinstance(entry, dict) and entry.get('expires', 0) > now]
            self.pyas_config['suppress_rules'] = kept
            self.save_config()

        return matched

    def _remember_suppression(self, request, reason, note, scope):
        """登记误报抑制;内容重读校验与永久允许同一套,文件被替换即拒绝。"""
        rule = request.rule

        if not rule or reason not in SUPPRESS_REASONS or scope not in SUPPRESS_SCOPES:
            return False

        if scope == 'file_rule' and not rule.get('detection'):
            return False

        fresh = self._make_alert_identity(rule['action'], rule['source'], rule['target'], json.loads(rule['detection']))
        if fresh != rule or request.done.is_set() or (request.deadline and request.deadline <= time.monotonic()):
            return False

        now = time.time()
        entry = {'id': uuid4().hex, 'scope': scope, 'sha256': rule['sha256'],
            'detection': rule['detection'] if scope == 'file_rule' else '',
            'action': rule['action'], 'reason': reason,
            'note': str(note or '').strip()[:200],
            'created': now, 'expires': now + SUPPRESS_TTL,
            'hits': 0, 'last_hit': 0, 'source': 'user'}

        with self._alert_policy_lock():
            old = self.pyas_config.get('suppress_rules', [])
            rules = [item for item in old if isinstance(item, dict)] if isinstance(old, list) else []
            duplicate = next((item for item in rules
                if item.get('sha256') == entry['sha256'] and item.get('scope') == scope
                and (scope == 'file' or item.get('detection') == entry['detection'])), None)

            if duplicate is not None:
                merged = {**duplicate, 'reason': entry['reason'], 'note': entry['note'],
                    'created': entry['created'], 'expires': entry['expires']}
                updated = [merged if item is duplicate else item for item in rules]
            else:
                if len(rules) >= MAX_RULES:
                    return False
                updated = [*rules, entry]

            self.pyas_config['suppress_rules'] = updated
            if self.save_config() is False:
                self.pyas_config['suppress_rules'] = old
                return False

        if hasattr(self, 'write_log'):
            self.write_log('INFO', 'False Positive Reported',
                source=rule['source'],
                detail=f"{scope} / {reason} / {rule['action']}", file_hash=rule['sha256'])
        return True

    # ---- 放行记录管理(设置页子页) ----

    def list_release_records(self):
        """列举永久允许与误报抑制,供设置页「放行记录」展示。"""
        now = time.time()

        with self._alert_policy_lock():
            allows = [
                item for item in self.pyas_config.get("alert_allow_rules", [])
                if isinstance(item, dict)
            ]
            suppress = [
                item for item in self.pyas_config.get("suppress_rules", [])
                if isinstance(item, dict) and item.get("expires", 0) > now
            ]

            permanent = [
                {
                    "key": item.get("key", ""),
                    "action": item.get("action", ""),
                    "source": item.get("source", ""),
                    "sha256": item.get("sha256", ""),
                    "hits": int(item.get("hits", 0)),
                    "created": float(item.get("created", 0) or 0),
                }
                for item in allows[:MAX_RULES]
            ]

            suppress_records = [
                {
                    "id": item.get("id", ""),
                    "action": item.get("action", ""),
                    # 抑制记录按内容哈希锚定,不保存文件路径;source 字段只记录创建者,不能当路径展示
                    "source": "",
                    "sha256": item.get("sha256", ""),
                    "reason": item.get("reason", ""),
                    "scope": item.get("scope", ""),
                    "days_left": max(1, int((item.get("expires", 0) - now) // 86400) + 1),
                    "hits": int(item.get("hits", 0)),
                    "created": float(item.get("created", 0) or 0),
                }
                for item in suppress[:MAX_RULES]
            ]

        return {"permanent": permanent, "suppress": suppress_records}

    def delete_release_record(self, kind, ident):
        """删除单条放行记录:kind='permanent'(按 key)或 'suppress'(按 id)。"""
        if not ident:
            return False

        with self._alert_policy_lock():
            if kind == "permanent":
                key = "alert_allow_rules"
                field = "key"
            elif kind == "suppress":
                key = "suppress_rules"
                field = "id"
            else:
                return False

            old = list(self.pyas_config.get(key, []) or [])
            kept = [
                item for item in old
                if not (isinstance(item, dict) and item.get(field) == ident)
            ]

            if len(kept) == len(old):
                return False

            self.pyas_config[key] = kept

            if self.save_config() is False:
                self.pyas_config[key] = old
                return False

        if hasattr(self, "write_log"):
            self.write_log("INFO", "Config Update", detail=f"Release record removed: {kind}/{str(ident)[:16]}")
        return True

    def clear_release_records(self, kind=None):
        """清除放行记录:kind=None 全清,'permanent'/'suppress' 分类清。"""
        with self._alert_policy_lock():
            changed = False

            if kind in (None, "permanent"):
                if self.pyas_config.get("alert_allow_rules"):
                    self.pyas_config["alert_allow_rules"] = []
                    changed = True

            if kind in (None, "suppress"):
                if self.pyas_config.get("suppress_rules"):
                    self.pyas_config["suppress_rules"] = []
                    changed = True

            if changed and self.save_config() is False:
                return False

            # 内存级重复决定同步失效
            self._recent_alert_decisions = {}

        if changed and hasattr(self, "write_log"):
            self.write_log("INFO", "Config Update", detail=f"Release records cleared: {kind or 'all'}")
        return True

    def _remember_alert_decision(self, request, choice, repeat=False):
        rule = request.rule
        if not rule:
            return choice != 'permanent' and not repeat
        # Re-read at confirmation. A queued file may have been replaced.
        fresh = self._make_alert_identity(rule['action'], rule['source'], rule['target'], json.loads(rule['detection']))
        if fresh != rule or request.done.is_set() or (request.deadline and request.deadline <= time.monotonic()):
            return False
        with self._alert_policy_lock():
            if choice == 'permanent':
                old = self.pyas_config.get('alert_allow_rules', [])
                rules = list(old) if isinstance(old, list) else []
                # 落库的条目带 hits/created,重复判断只能按身份字段比
                if not any(isinstance(item, dict) and _identity_view(item) == rule for item in rules[:MAX_RULES]):
                    if len(rules) >= MAX_RULES:
                        return False
                    entry = {**rule, 'created': time.time(), 'hits': 0}
                    self.pyas_config['alert_allow_rules'] = [*rules, entry]
                    if self.save_config() is False:
                        self.pyas_config['alert_allow_rules'] = old
                        return False
            elif repeat:
                recent = getattr(self, '_recent_alert_decisions', None)
                if recent is None:
                    recent = self._recent_alert_decisions = {}
                if len(recent) >= MAX_RULES:
                    recent.pop(next(iter(recent)))
                now = time.monotonic()
                recent[rule['key']] = {'rule': rule, 'choice': choice,
                    'until': now + REPEAT_SECONDS, 'uses': REPEAT_USES,
                    'created': now}
        if hasattr(self, 'write_log'):
            self.write_log('WARN' if choice == 'permanent' else 'INFO', 'Alert Decision Remembered',
                source=rule['source'], detail=f"{rule['action']} / {rule['target']} / {choice} / repeat={repeat}", file_hash=rule['sha256'])
        return True

    def clear_alert_decisions(self):
        with self._alert_policy_lock():
            old = self.pyas_config.get('alert_allow_rules', [])
            self.pyas_config['alert_allow_rules'] = []
            if self.save_config() is False:
                self.pyas_config['alert_allow_rules'] = old
                return False
            self._recent_alert_decisions = {}
        return True
