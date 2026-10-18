"""Installer lifecycle tests with fake Win32 calls; not native ABI certification."""
from contextlib import contextmanager, ExitStack
import hashlib
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import PYAS_UpdateInstall as install
from PYAS_FileTrust import locked_read

class InstallerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.file = Path(self.directory.name) / 'fixture installer.exe'
        self.file.write_bytes(b'fixture')
        self.digest = hashlib.sha256(b'fixture').hexdigest()
        self.closed = threading.Event()
        self.release = threading.Event(); self.release.set()
        self.waiting = threading.Event()
        self.exited = threading.Event()
        @contextmanager
        def guard(path):
            try:
                with open(path, 'rb') as stream:
                    yield stream
            finally:
                self.closed.set()
        self.guard = guard
        def wait(handle, timeout):
            self.waiting.set(); self.release.wait(2); return 0
        def code(handle, pointer): pointer._obj.value = 0; return True
        def system(buffer, size): buffer.value = 'C:/Windows/System32'; return len(buffer.value)
        self.kernel = SimpleNamespace(WaitForSingleObject=Mock(side_effect=wait),
            GetExitCodeProcess=Mock(side_effect=code), CloseHandle=Mock(), GetSystemDirectoryW=Mock(side_effect=system))
        def execute(pointer): pointer._obj.hProcess = 123; return True
        self.shell = SimpleNamespace(ShellExecuteExW=Mock(side_effect=execute))
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(install, 'locked_read', self.guard))
        self.stack.enter_context(patch.object(install, 'os', SimpleNamespace(name='nt', path=os.path)))
        self.stack.enter_context(patch.object(install.ctypes, 'WinDLL', side_effect=lambda name, **kw: self.kernel if name == 'kernel32' else self.shell, create=True))
        self.stack.enter_context(patch.object(install.ctypes, 'get_last_error', return_value=5, create=True))
        self.stack.enter_context(patch.object(install.ctypes, 'WinError', side_effect=lambda code: OSError(code, 'native failure'), create=True))

    def tearDown(self):
        self.release.set()
        if self.waiting.is_set(): self.closed.wait(2)

    def test_lock_is_retained_until_installer_exit_and_handle_is_closed(self):
        self.release.clear()
        callback = Mock(side_effect=lambda code: self.exited.set())
        self.assertTrue(install.launch_verified_installer(str(self.file), self.digest, callback))
        self.assertTrue(self.waiting.wait(1))
        self.assertFalse(self.closed.is_set())
        self.release.set(); self.assertTrue(self.exited.wait(1))
        self.assertTrue(self.closed.is_set())
        self.kernel.CloseHandle.assert_called_once_with(123)
        callback.assert_called_once_with(0)

    def test_mismatched_digest_closes_file_without_any_native_launch(self):
        with self.assertRaises(ValueError):
            install.launch_verified_installer(str(self.file), '0' * 64)
        self.assertTrue(self.closed.is_set())
        self.shell.ShellExecuteExW.assert_not_called()

    def test_shell_failure_releases_the_pinned_file(self):
        self.shell.ShellExecuteExW.side_effect = None
        self.shell.ShellExecuteExW.return_value = False
        with self.assertRaises(OSError): install.launch_verified_installer(str(self.file), self.digest)
        self.assertTrue(self.closed.wait(1))
        self.kernel.CloseHandle.assert_not_called()

    def test_unknown_accepted_launch_is_reported_as_uncertain(self):
        self.shell.ShellExecuteExW.side_effect = None
        self.shell.ShellExecuteExW.return_value = True
        with self.assertRaises(install.InstallLaunchUncertain):
            install.launch_verified_installer(str(self.file), self.digest)
        self.assertTrue(self.closed.wait(1))

    def test_monitor_allocation_failure_occurs_before_launch(self):
        bad = Mock(); bad.start.side_effect = RuntimeError('no monitor')
        with patch.object(install, 'threading', SimpleNamespace(Thread=Mock(return_value=bad), Event=threading.Event)):
            with self.assertRaises(RuntimeError): install.launch_verified_installer(str(self.file), self.digest)
        self.assertTrue(self.closed.is_set())
        self.shell.ShellExecuteExW.assert_not_called()

    def test_msi_uses_explicit_system_msiexec_with_quoted_path(self):
        package = self.file.with_suffix('.msi')
        package.write_bytes(b'fixture')
        captured = {}
        def launch(pointer):
            captured.update(file=pointer._obj.lpFile, parameters=pointer._obj.lpParameters)
            pointer._obj.hProcess = 123
            return True
        self.shell.ShellExecuteExW.side_effect = launch
        self.assertTrue(install.launch_verified_installer(str(package), self.digest, lambda code: self.exited.set()))
        self.assertTrue(self.exited.wait(1))
        self.assertEqual(os.path.basename(captured['file']), 'msiexec.exe')
        self.assertEqual(os.path.basename(os.path.dirname(captured['file'])), 'System32')
        self.assertIn('"' + os.path.realpath(os.path.abspath(str(package))) + '"', captured['parameters'])

class WindowsFileSharingTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'requires real Windows FILE_SHARE_READ semantics')
    def test_real_windows_guard_denies_writer_and_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'fixture.bin'
            replacement = Path(directory) / 'other.bin'
            file.write_bytes(b'original'); replacement.write_bytes(b'changed')
            with locked_read(file):
                with self.assertRaises(OSError): file.write_bytes(b'overwrite')
                with self.assertRaises(OSError): os.replace(replacement, file)
            self.assertEqual(file.read_bytes(), b'original')

if __name__ == '__main__': unittest.main()
