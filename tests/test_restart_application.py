"""Restart-to-apply: the saved policy is only read at startup.

A restart that cannot happen must say so. Silently doing nothing leaves the user
with a single confirm button that appears broken.
"""
import os
from pathlib import Path
from unittest.mock import Mock, patch
import unittest
import PYAS

ROOT = Path(__file__).resolve().parents[1]


class RestartApplicationTests(unittest.TestCase):
    def owner(self):
        # The bridge exposes every public _MainMixin method, so the restart entry
        # is reachable from the page without any window being constructed.
        return object.__new__(PYAS.WindowAPI)

    def test_development_build_reports_failure_instead_of_restarting(self):
        with patch.object(PYAS.sys, 'frozen', False, create=True), \
             patch.object(PYAS.subprocess, 'Popen') as popen:
            self.assertFalse(self.owner().restart_application())
        self.assertEqual(popen.call_count, 0)

    def test_missing_launcher_reports_failure(self):
        with patch.object(PYAS.sys, 'frozen', True, create=True), \
             patch.object(PYAS.os.path, 'isfile', return_value=False), \
             patch.object(PYAS.subprocess, 'Popen') as popen:
            self.assertFalse(self.owner().restart_application())
        self.assertEqual(popen.call_count, 0)

    def test_launcher_is_asked_to_wait_for_this_process(self):
        owner = self.owner()
        owner.start_daemon_thread = Mock()
        with patch.object(PYAS.sys, 'frozen', True, create=True), \
             patch.object(PYAS.os.path, 'isfile', return_value=True), \
             patch.object(PYAS.os, 'getpid', return_value=4321), \
             patch.object(PYAS.os.path, 'dirname', return_value=r'C:\Program Files\PYAS'), \
             patch.object(PYAS.subprocess, 'Popen') as popen:
            self.assertTrue(owner.restart_application())
        command = popen.call_args.args[0]
        self.assertTrue(command[0].endswith('PYAS_Launcher.exe'))
        # The pid is the whole protocol: the launcher must wait for this process,
        # otherwise the new instance hits the single-instance mutex and forwards.
        self.assertEqual(command[1:], ['--restart', '4321'])
        self.assertEqual(popen.call_args.kwargs['cwd'], r'C:\Program Files\PYAS')
        self.assertEqual(owner.start_daemon_thread.call_count, 1)

    def test_launcher_process_is_detached_from_this_one(self):
        owner = self.owner()
        owner.start_daemon_thread = Mock()
        with patch.object(PYAS.sys, 'frozen', True, create=True), \
             patch.object(PYAS.os.path, 'isfile', return_value=True), \
             patch.object(PYAS.subprocess, 'Popen') as popen:
            owner.restart_application()
        flags = popen.call_args.kwargs['creationflags']
        self.assertTrue(flags & 0x00000008, 'DETACHED_PROCESS keeps the launcher alive')
        self.assertTrue(flags & 0x08000000, 'no console window may flash')

    def test_closing_application_does_not_restart(self):
        owner = self.owner()
        owner.closing = True
        with patch.object(PYAS.sys, 'frozen', True, create=True), \
             patch.object(PYAS.subprocess, 'Popen') as popen:
            self.assertFalse(owner.restart_application())
        self.assertEqual(popen.call_count, 0)

    def test_spawn_failure_is_reported_not_raised(self):
        owner = self.owner()
        with patch.object(PYAS.sys, 'frozen', True, create=True), \
             patch.object(PYAS.os.path, 'isfile', return_value=True), \
             patch.object(PYAS.subprocess, 'Popen', side_effect=OSError('denied')):
            self.assertFalse(owner.restart_application())

    def test_refused_shutdown_tells_the_page_to_recover(self):
        # close() returns False when a driver cannot be stopped. Without this the
        # page keeps its only button disabled and the panel is stuck forever.
        owner = self.owner()
        owner.close = Mock(return_value=False)
        owner._window = Mock()
        with patch.object(PYAS.time, 'sleep'):
            owner._restart_after_reply()
        called = owner._window.evaluate_js.call_args.args[0]
        self.assertIn('pyasPolicyRestartFailed', called)

    def test_successful_shutdown_exits_without_touching_the_page(self):
        owner = self.owner()
        owner.close = Mock(return_value=None)
        owner._window = Mock()
        with patch.object(PYAS.time, 'sleep'):
            owner._restart_after_reply()
        self.assertEqual(owner._window.evaluate_js.call_count, 0)


class LauncherRestartContractTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / 'Plugins' / 'Bootstrap' / 'PYAS_Launcher.cpp').read_text(encoding='utf-8')

    def test_launcher_waits_for_the_previous_instance(self):
        self.assertIn('--restart ', self.text)
        self.assertIn('OpenProcess(SYNCHRONIZE', self.text)
        self.assertIn('WaitForSingleObject(process, 60000)', self.text)

    def test_restart_argument_is_not_forwarded_to_pyas(self):
        # A leftover flag would reach the GUI as an unknown argument.
        self.assertIn('waitForPid = forwarded.substr(10);', self.text)
        self.assertIn('forwarded.clear();', self.text)


if __name__ == '__main__': unittest.main()
