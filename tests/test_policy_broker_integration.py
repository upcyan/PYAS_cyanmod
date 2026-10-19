"""Real Windows request/broker round trips in an isolated temporary policy root.

Never touches ProgramData/PYAS.Policy and never triggers an interactive UAC prompt.
The CI runner is elevated; only the fixed destination is redirected by the test.
"""
import base64
from contextlib import ExitStack
import ctypes
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import PYAS_PolicyWindows as windows
from PYAS_Policy import PolicyDenied


@unittest.skipUnless(os.name == 'nt', 'requires real Windows file handles and PowerShell')
class BrokerIntegrationTests(unittest.TestCase):
    def setUp(self):
        if not ctypes.windll.shell32.IsUserAnAdmin():
            self.skipTest('isolated broker requires an elevated Windows test runner')
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.root = self.directory / 'ProtectedPolicy'
        self.stack.enter_context(patch.object(windows, 'user_data_dir', return_value=str(self.directory)))
        self.backend = windows.WindowsPolicyBackend()
        self.backend.root = str(self.root)
        self.backend.policy_file = str(self.root / 'Config.json')
        self.lease = windows.WindowsPolicyLease(self.backend, {'process_switch'}, None, 'initialize', True)
        self.backend.leases.add(self.lease)
        self.addCleanup(self.cleanup_lease)
        self.processes = []
        script = windows._script
        popen = subprocess.Popen
        def isolated_script(request, digest):
            text = base64.b64decode(script(request, digest)).decode('utf-16-le')
            # Redirect only the final $root: the machine-scope lookup above it is
            # part of what this test must exercise.
            fixed = "$root=[IO.Path]::Combine($programData,'PYAS.Policy')"
            self.assertEqual(text.count(fixed), 1)
            text = text.replace(fixed, "$root='" + str(self.root).replace("'", "''") + "'")
            # Until the production diagnostic channel exists, expose the original
            # swallowed exception to this test only; do not alter broker behavior.
            text = text.replace('}catch{exit $stage}finally{',
                '}catch{[Console]::Error.WriteLine($_.Exception.ToString());exit $stage}finally{')
            return base64.b64encode(text.encode('utf-16-le')).decode('ascii')
        def captured_popen(*args, **kwargs):
            kwargs['stdout'] = subprocess.PIPE
            kwargs['stderr'] = subprocess.PIPE
            process = popen(*args, **kwargs)
            self.processes.append(process)
            return process
        self.stack.enter_context(patch.object(windows, '_script', side_effect=isolated_script))
        self.stack.enter_context(patch.object(windows.subprocess, 'Popen', side_effect=captured_popen))

    def cleanup_lease(self):
        self.lease.close()
        for process in getattr(self, 'processes', []):
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)

    def start(self):
        try:
            self.lease.start()
        except Exception as error:
            outputs = []
            for process in self.processes:
                if process.poll() is not None:
                    out, err = process.communicate(timeout=10)
                    outputs.append((process.returncode, out.decode('utf-8', 'replace'),
                                    err.decode('utf-8', 'replace')))
            self.fail(str(error) + '\nBroker outputs: ' + repr(outputs))

    def test_frozen_helper_round_trip_from_protected_installation(self):
        import shutil
        import uuid
        repo = Path(__file__).resolve().parents[1]
        built = subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
            '--onefile', '--name', 'PolicyProbe', '--distpath', str(self.directory / 'dist'),
            '--workpath', str(self.directory / 'build'), '--specpath', str(self.directory),
            '--paths', str(repo), str(repo / 'tests' / 'policy_frozen_probe.py')],
            cwd=repo, capture_output=True, timeout=180)
        self.assertEqual(built.returncode, 0, built.stderr.decode('utf-8', 'replace')[-6000:])
        # Match the user's protected installed onefile executable, rather than a
        # source-mode test that bypasses helper_main or installation verification.
        installed = Path(os.environ['ProgramFiles']) / ('PYAS Policy Probe ' + uuid.uuid4().hex)
        installed.mkdir()
        try:
            executable = installed / 'PolicyProbe.exe'
            shutil.copyfile(self.directory / 'dist' / 'PolicyProbe.exe', executable)
            env = dict(os.environ, PYAS_TEST_POLICY_ROOT=str(self.root),
                       PYINSTALLER_RESET_ENVIRONMENT='1')
            result = subprocess.run([str(executable)], env=env, capture_output=True, timeout=150)
            self.assertEqual(result.returncode, 0,
                             result.stdout.decode('utf-8', 'replace') + result.stderr.decode('utf-8', 'replace'))
            self.assertIn(b'FROZEN_POLICY_COMMIT_OK', result.stdout)
        finally:
            shutil.rmtree(installed)

    def test_authorize_commit_and_confirm_real_policy(self):
        self.start()
        self.assertTrue(self.lease.authorized)
        document = self.lease.commit({'process_switch': True})
        self.assertTrue(document['process_switch'])
        self.assertEqual(document['_request'], self.lease.nonce)
        self.assertEqual(self.backend.read_policy()['_request'], self.lease.nonce)
        self.assertTrue(self.lease.committed)
        self.assertFalse((self.root / ('.auth-' + self.lease.nonce + '.json')).exists())

    def test_real_owner_channel_verification_in_another_process(self):
        self.lease._open_channel()
        # Python is not installed as PYAS. Bypass only its installation-location
        # guard; parent image/PID/duplicate handle/hash/file identity/share checks
        # all run unmodified against a genuinely separate process.
        code = (
            'import sys; import PYAS_PolicyWindows as w; '
            'w.installed_helper_trusted=lambda:True; '
            'from PYAS_PolicyNative import verify_request_owner; '
            'handles=verify_request_owner(sys.argv[1],sys.argv[2]); '
            '[w._close(h) for h in reversed(handles)]; print("OWNER_CHANNEL_OK")'
        )
        result = subprocess.run([sys.executable, '-c', code, self.lease.path, self.lease.digest],
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout.decode('utf-8', 'replace') +
                         result.stderr.decode('utf-8', 'replace'))
        self.assertIn(b'OWNER_CHANNEL_OK', result.stdout)

    def test_out_of_scope_update_never_commits(self):
        self.start()
        with self.assertRaises(PolicyDenied):
            self.lease.commit({'network_switch': True})
        self.assertFalse(Path(self.backend.policy_file).exists())


if __name__ == '__main__':
    unittest.main()
