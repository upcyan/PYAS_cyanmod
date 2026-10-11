"""Narrow, content-bound exceptions for interactive alerts, never scan exclusions."""
import hashlib
import json
import re
import os
import time
from contextlib import contextmanager
from uuid import uuid4

MAX_RULES = 256
REPEAT_SECONDS = 30
REPEAT_USES = 20

# 误报抑制:只锚定文件内容(SHA-256)或其签名者证书,绝不锚定目录/进程名/扩展名。
# scope 'file_rule' = 该内容 × 该检测结果(L1);'file' = 该内容 × 全部检测(L2);
# 'signer' = 同一 Authenticode 签名者证书(L3,签名被替换即失效)
SUPPRESS_TTL = 90 * 86400
SUPPRESS_SCOPES = ('file_rule', 'file', 'signer')
SUPPRESS_REASONS = ('dev_tool', 'installer', 'enterprise', 'game_patch', 'other')


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
            if isinstance(rules, list) and any(isinstance(item, dict) and item == rule for item in rules[:MAX_RULES]):
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
                return item['choice']
        return None

    def _match_suppression_locked(self, rule):
        """内容锚定抑制匹配;命中即累计审计计数,过期条目顺带清理。"""
        entries = self.pyas_config.get('suppress_rules', [])

        if not isinstance(entries, list) or not entries or not rule.get('sha256'):
            return None

        now = time.time()
        changed = False
        matched = None
        signer = None

        for entry in entries[:MAX_RULES]:
            if not isinstance(entry, dict):
                changed = True
                continue

            if entry.get('expires', 0) <= now:
                changed = True
                continue

            scope = entry.get('scope')

            if scope == 'signer':
                if not entry.get('signer'):
                    continue

                if signer is None:
                    signer = self._rule_signer(rule)

                if signer and entry.get('signer') == signer:
                    matched = entry
                    break

                continue

            if entry.get('sha256') != rule.get('sha256'):
                continue

            if scope == 'file' or (
                scope == 'file_rule' and entry.get('detection') == rule.get('detection')
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

        signer = self._rule_signer(rule) if scope == 'signer' else None

        if scope == 'signer' and not signer:
            return False

        fresh = self._make_alert_identity(rule['action'], rule['source'], rule['target'], json.loads(rule['detection']))
        if fresh != rule or request.done.is_set() or (request.deadline and request.deadline <= time.monotonic()):
            return False

        now = time.time()
        entry = {'id': uuid4().hex, 'scope': scope, 'sha256': rule['sha256'],
            'detection': rule['detection'] if scope == 'file_rule' else '',
            'signer': signer or '',
            'action': rule['action'], 'reason': reason,
            'note': str(note or '').strip()[:200],
            'created': now, 'expires': now + SUPPRESS_TTL,
            'hits': 0, 'last_hit': 0, 'source': 'user'}

        with self._alert_policy_lock():
            old = self.pyas_config.get('suppress_rules', [])
            rules = [item for item in old if isinstance(item, dict)] if isinstance(old, list) else []
            duplicate = next((item for item in rules
                if item.get('scope') == scope and (
                    (scope == 'signer' and item.get('signer') == signer)
                    or (item.get('sha256') == entry['sha256']
                        and (scope == 'file' or item.get('detection') == entry['detection'])))), None)

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
                if rule not in rules:
                    if len(rules) >= MAX_RULES:
                        return False
                    self.pyas_config['alert_allow_rules'] = [*rules, rule]
                    if self.save_config() is False:
                        self.pyas_config['alert_allow_rules'] = old
                        return False
            elif repeat:
                recent = getattr(self, '_recent_alert_decisions', None)
                if recent is None:
                    recent = self._recent_alert_decisions = {}
                if len(recent) >= MAX_RULES:
                    recent.pop(next(iter(recent)))
                recent[rule['key']] = {'rule': rule, 'choice': choice,
                    'until': time.monotonic() + REPEAT_SECONDS, 'uses': REPEAT_USES}
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

    def _rule_signer(self, rule):
        """事件文件的签名者指纹,按内容哈希缓存;取不到返回 None(不匹配)。"""
        digest = rule.get('sha256')
        source = rule.get('source')

        if not digest or not source:
            return None

        cache = getattr(self, '_signer_hash_cache', None)
        if cache is None:
            cache = self._signer_hash_cache = {}

        if digest not in cache:
            cache[digest] = file_signer_hash(source)

        return cache[digest]

    def get_suppression_rules(self):
        """管理页数据:先清理过期条目,再返回按创建时间倒序的脱敏列表。"""
        with self._alert_policy_lock():
            entries = [e for e in self.pyas_config.get('suppress_rules', []) if isinstance(e, dict)]
            now = time.time()
            kept = [e for e in entries if e.get('expires', 0) > now]

            if len(kept) != len(entries):
                self.pyas_config['suppress_rules'] = kept
                self.save_config()

        return [{
            'id': e.get('id', ''), 'scope': e.get('scope', ''), 'action': e.get('action', ''),
            'sha256': e.get('sha256', ''), 'signer': e.get('signer', ''),
            'reason': e.get('reason', ''), 'note': e.get('note', ''),
            'source': e.get('source', 'user'), 'hits': int(e.get('hits', 0)),
            'created': e.get('created', 0), 'expires': e.get('expires', 0),
            'last_hit': e.get('last_hit', 0),
        } for e in sorted(kept, key=lambda item: -item.get('created', 0))]

    def delete_suppression_rule(self, rule_id):
        """按 id 删除一条抑制规则;id 不存在返回 False。"""
        rid = str(rule_id or '')

        with self._alert_policy_lock():
            old = self.pyas_config.get('suppress_rules', [])
            rules = [e for e in old if isinstance(e, dict)]
            kept = [e for e in rules if e.get('id') != rid]

            if len(kept) == len(rules):
                return False

            self.pyas_config['suppress_rules'] = kept

            if self.save_config() is False:
                self.pyas_config['suppress_rules'] = old
                return False

        if hasattr(self, 'write_log'):
            self.write_log('INFO', 'Suppression Rule Deleted', detail=rid)
        return True

    def get_ai_rule_drafts(self):
        """待审核的 AI 抑制规则草案(创建时间倒序)。"""
        with self._alert_policy_lock():
            drafts = [d for d in self.pyas_config.get('ai_rule_drafts', []) if isinstance(d, dict)]

        return sorted(drafts, key=lambda item: -item.get('created', 0))

    def resolve_ai_rule_draft(self, draft_id, approve):
        """批准:草案转为 scope 'file' 的抑制规则(source='ai');拒绝:仅移除草案。"""
        did = str(draft_id or '')

        with self._alert_policy_lock():
            old = self.pyas_config.get('ai_rule_drafts', [])
            drafts = [d for d in old if isinstance(d, dict)]
            draft = next((d for d in drafts if d.get('id') == did), None)

            if draft is None:
                return False

            remaining = [d for d in drafts if d is not draft]
            self.pyas_config['ai_rule_drafts'] = remaining

            if approve:
                rules = [e for e in self.pyas_config.get('suppress_rules', []) if isinstance(e, dict)]
                duplicate = any(e.get('sha256') == draft.get('sha256') and e.get('scope') == 'file'
                    for e in rules)

                if not duplicate and len(rules) < MAX_RULES:
                    now = time.time()
                    entry = {'id': uuid4().hex, 'scope': 'file', 'sha256': draft['sha256'],
                        'detection': '', 'signer': '', 'action': draft.get('action', ''),
                        'reason': draft.get('reason', 'other'), 'note': str(draft.get('note', ''))[:200],
                        'created': now, 'expires': now + SUPPRESS_TTL,
                        'hits': 0, 'last_hit': 0, 'source': 'ai'}
                    self.pyas_config['suppress_rules'] = [*rules, entry]

            if self.save_config() is False:
                self.pyas_config['ai_rule_drafts'] = old
                return False

        if hasattr(self, 'write_log'):
            self.write_log('INFO', 'AI Draft Resolved',
                detail=f"{did} / {'approved' if approve else 'rejected'}",
                file_hash=draft.get('sha256', ''))
        return True

    def generate_ai_rule_drafts(self):
        """把近期放行记录喂给模型,归纳候选抑制规则草案;产出须用户审核。"""
        from PYAS_AI import request_rule_drafts

        base_url, model, api_key = self._ai_endpoint_config()

        if not base_url or not model:
            return {'ok': False, 'error': 'missing_config'}

        evidence = {}

        for entry in list(getattr(self, 'logs_data', []) or []):
            detail = str(entry.get('detail', ''))
            digest = str(entry.get('file_hash', '')).lower()
            if 'Alert Decision Remembered' not in str(entry.get('action', '')):
                continue
            if ' / allow /' not in detail or not re.fullmatch(r'[0-9a-f]{64}', digest or ''):
                continue
            item = evidence.setdefault(digest, {'sha256': digest, 'count': 0, 'action': '', 'example': ''})
            item['count'] += 1
            item['action'] = detail.split(' / ')[0]
            if not item['example']:
                item['example'] = str(entry.get('source', ''))[-120:]

        candidates = sorted(evidence.values(), key=lambda item: -item['count'])[:12]

        if not candidates:
            return {'ok': False, 'error': 'no_data'}

        verdict = request_rule_drafts(base_url, model, api_key, candidates)

        if verdict is None:
            return {'ok': False, 'error': 'ai_unavailable'}

        with self._alert_policy_lock():
            existing_rules = {e.get('sha256') for e in self.pyas_config.get('suppress_rules', [])
                if isinstance(e, dict) and e.get('scope') == 'file'}
            drafts = [d for d in self.pyas_config.get('ai_rule_drafts', []) if isinstance(d, dict)]
            known = {d.get('sha256') for d in drafts}
            added = 0

            for item in verdict:
                digest = item.get('sha256', '')

                if digest in existing_rules or digest in known:
                    continue

                if len(drafts) >= MAX_RULES:
                    break

                drafts.append({'id': uuid4().hex, 'sha256': digest,
                    'reason': item.get('reason', 'other'), 'note': str(item.get('note', ''))[:200],
                    'action': next((c['action'] for c in candidates if c['sha256'] == digest), ''),
                    'created': time.time(), 'status': 'pending'})
                known.add(digest)
                added += 1

            if added:
                self.pyas_config['ai_rule_drafts'] = drafts
                if self.save_config() is False:
                    return {'ok': False, 'error': 'save_failed'}

        return {'ok': True, 'added': added}


def file_signer_hash(path, runner=None):
    """Authenticode 签名者证书的 SHA-1 指纹(十六进制);无签名/失败/非 Windows 返回 None。

    经 PowerShell Get-AuthenticodeSignature 取签名者证书指纹;调用方必须按
    文件内容哈希缓存结果,避免在事件路径上反复 spawn。"""
    import re
    import subprocess

    if os.name != 'nt':
        return None

    command = [
        os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                     'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
        '$s = Get-AuthenticodeSignature -LiteralPath $args[0];'
        'if ($s.SignerCertificate) { $s.SignerCertificate.Thumbprint }',
        str(path),
    ]
    try:
        result = (runner or subprocess.run)(command, capture_output=True, timeout=20, text=True)
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None

    match = re.search(r'\b([0-9A-F]{40})\b', result.stdout or '')
    return match.group(1) if match else None

