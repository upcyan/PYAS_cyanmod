"""策略 relaunch 协议:请求头携带 relaunch_pid,helper 提交成功后经 launcher
等旧实例退出并以管理员接管 —— 「一次授权 + 一次重启」合并为一次 UAC。"""

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PYAS_Policy import PolicyStore
from PYAS_PolicyWindows import WindowsPolicyLease, _relaunch_elevated_from_request


class HeaderTests(unittest.TestCase):
    def test_relaunch_pid_lands_in_signed_header(self):
        lease = WindowsPolicyLease(None, {'process_switch'}, 'rev', 'setting:process_switch',
                                   False, relaunch_pid=4242)

        self.assertEqual(lease.header['relaunch_pid'], 4242)

    def test_no_relaunch_by_default(self):
        lease = WindowsPolicyLease(None, {'process_switch'}, 'rev', 'change', False)

        self.assertNotIn('relaunch_pid', lease.header)


class BeginRelayTests(unittest.TestCase):
    def test_begin_relays_relaunch_pid_to_backend(self):
        seen = {}

        class Backend:
            def __init__(self):
                self.values = {}
                self.status = {'state': 'ready', 'error': ''}
                self.revision = 'base'

            def read_user(self): return {}
            def read_policy(self): return None
            def write_user(self, value): pass

            def authorize(self, scope, revision, operation, initialize, relaunch_pid=None):
                seen['relaunch_pid'] = relaunch_pid

                class Lease:
                    authorized = True
                    committed = False
                    def start(self): pass
                    def close(self): pass
                return Lease()

            def cancel(self): pass

        store = PolicyStore({'process_switch': False}, Backend())
        store.revision = 'base'
        store.begin({'process_switch'}, 'change', False, relaunch_pid=99)

        self.assertEqual(seen['relaunch_pid'], 99)


class RelaunchFromRequestTests(unittest.TestCase):
    def write_request(self, tmp, header):
        raw = json.dumps(header).encode('utf-8')
        path = Path(tmp) / 'nonce.request'
        path.write_bytes(struct.pack('<I', len(raw)) + raw)
        return str(path)

    def test_launches_launcher_waiting_for_old_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            request = self.write_request(tmp, {'nonce': 'a' * 32, 'relaunch_pid': 777})
            launcher = Path(tmp) / 'PYAS_Launcher.exe'
            launcher.write_bytes(b'')
            calls = []

            with patch('PYAS_PolicyWindows.sys') as fake_sys, \
                 patch('PYAS_PolicyWindows.os.path.isfile', return_value=True), \
                 patch('PYAS_PolicyWindows.subprocess.Popen') as popen:
                fake_sys.executable = str(Path(tmp) / 'PYAS.exe')
                _relaunch_elevated_from_request(request)

                self.assertEqual(popen.call_count, 1)
                calls.append(popen.call_args)
                self.assertEqual(calls[0].args[0][0], str(launcher))
                self.assertIn('--restart', calls[0].args[0])
                self.assertIn('777', calls[0].args[0])

    def test_missing_or_invalid_pid_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            launcher = Path(tmp) / 'PYAS_Launcher.exe'
            launcher.write_bytes(b'')

            for header in ({'nonce': 'a' * 32}, {'nonce': 'a' * 32, 'relaunch_pid': -1},
                           {'nonce': 'a' * 32, 'relaunch_pid': '777'}):
                request = self.write_request(tmp, header)

                with patch('PYAS_PolicyWindows.sys') as fake_sys, \
                     patch('PYAS_PolicyWindows.os.path.isfile', return_value=True), \
                     patch('PYAS_PolicyWindows.subprocess.Popen') as popen:
                    fake_sys.executable = str(Path(tmp) / 'PYAS.exe')
                    _relaunch_elevated_from_request(request)

                    self.assertEqual(popen.call_count, 0, f"pid={header.get('relaunch_pid')!r} 不应触发重启")

    def test_broken_request_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            request = Path(tmp) / 'nonce.request'
            request.write_bytes(b'\x01\x02\x03')

            with patch('PYAS_PolicyWindows.subprocess.Popen') as popen:
                _relaunch_elevated_from_request(str(request))

                self.assertEqual(popen.call_count, 0)


if __name__ == "__main__":
    unittest.main()
