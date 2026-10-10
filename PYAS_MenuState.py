"""Per-user menu registration attempts; failed packages are not retried at startup."""
import hashlib
import json
import os
import threading
from pathlib import Path
from PYAS_Storage import atomic_write_json


class MenuRegistrationState:
    def __init__(self, install_path):
        self.lock = threading.RLock()
        self.file = os.path.join(os.environ['LOCALAPPDATA'], 'PYAS', 'Menu', 'attempt.json')
        digest = hashlib.sha256(os.path.normcase(os.path.abspath(install_path)).encode('utf-8'))
        menu = Path(install_path) / 'Menu'
        for path in sorted([*menu.glob('*.msix'), menu / 'menu_cert.cer']):
            digest.update(path.name.encode('utf-8'))
            try:
                digest.update(path.read_bytes())
            except OSError:
                digest.update(b'missing')
        self.fingerprint = digest.hexdigest()
        try:
            with open(self.file, encoding='utf-8') as stream:
                state = json.load(stream)
            self.state = state if isinstance(state, dict) and state.get('fingerprint') == self.fingerprint else {}
        except (OSError, ValueError):
            self.state = {}

    def failed(self):
        with self.lock:
            return self.state.get('result') == 'failed'

    def record(self, success, error=''):
        with self.lock:
            notified = self.state.get('notified', False) if self.failed() else False
            self.state = {'fingerprint': self.fingerprint, 'result': 'success' if success else 'failed',
                          'error': str(error)[:1500], 'notified': notified if not success else False}
            atomic_write_json(self.file, self.state)

    def take_notice(self):
        with self.lock:
            if not self.failed() or self.state.get('notified'):
                return ''
            self.state['notified'] = True
            atomic_write_json(self.file, self.state)
            return self.state.get('error', '')
