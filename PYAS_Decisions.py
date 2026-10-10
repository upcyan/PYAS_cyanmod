"""Narrow, content-bound exceptions for interactive alerts, never scan exclusions."""
import hashlib
import json
import os
import time
from contextlib import contextmanager

MAX_RULES = 256
REPEAT_SECONDS = 30
REPEAT_USES = 20


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
