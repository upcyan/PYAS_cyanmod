"""The elevated helper can die inside the frozen bootloader, before Python runs.

Nothing in this process can then report why, so the native launcher redirects
that child's stderr to one fixed file. These tests hold that contract in place:
without it an exit code of 1 stays unexplained forever.
"""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import PYAS_PolicyWindows as windows

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / 'Plugins' / 'Bootstrap' / 'PYAS_Launcher.cpp'

SAMPLE = '\n'.join([
    '==== [2026-10-19 09:38:42.753] policy helper launch ====',
    'elevated=1 pid=45836 args=3',
    'executable=C:\\Program Files\\PYAS\\PYAS.exe',
    'inherited _PYI_APPLICATION_HOME_DIR=<unset>',
    'reset=1',
    '--- child output ---',
    "FATAL: Failed to load Python DLL 'python314.dll'.",
    'LoadLibrary: The specified module could not be found.',
    '==== [2026-10-19 09:38:43.493] exit=1 after 0s ====',
    '',
])


class LauncherRedirectTests(unittest.TestCase):
    def setUp(self):
        self.text = LAUNCHER.read_text(encoding='utf-8')

    def test_helper_child_owns_a_redirected_fixed_log(self):
        self.assertIn("policy-helper-bootstrap.log", self.text)
        self.assertIn('STARTF_USESTDHANDLES', self.text)
        self.assertIn('startup.hStdError = log', self.text)
        self.assertIn('startup.hStdOutput = log', self.text)
        self.assertIn('bInheritHandle = TRUE', self.text)
        self.assertIn('inheritHandles = TRUE', self.text)

    def test_log_path_is_never_taken_from_the_request(self):
        # A caller-supplied path would turn the elevated launcher into an
        # arbitrary-file write; the location must come from CSIDL only.
        self.assertIn('CSIDL_COMMON_APPDATA', self.text)
        self.assertNotIn('lpParameters', self.text)
        self.assertNotIn('GetCommandLineW', self.text)

    def test_planted_reparse_point_disables_logging_instead_of_following_it(self):
        self.assertIn('FILE_ATTRIBUTE_REPARSE_POINT', self.text)
        self.assertIn('FILE_FLAG_OPEN_REPARSE_POINT', self.text)
        self.assertIn('IsLink(root) || IsLink(folder)', self.text)

    def test_only_the_hidden_policy_helper_is_redirected(self):
        self.assertIn('waitForExit && forwarded.find(kPolicyHelperFlag)', self.text)
        self.assertIn('if (log) {', self.text)

    def test_inherited_onefile_state_is_recorded_before_the_reset(self):
        # The prime suspect for a bootloader abort is a stale inherited _MEI
        # directory, so the launcher must log it as received.
        self.assertIn('_PYI_APPLICATION_HOME_DIR', self.text)
        self.assertIn('inherited PYINSTALLER_RESET_ENVIRONMENT=', self.text)
        self.assertLess(self.text.index('inherited _PYI_APPLICATION_HOME_DIR'),
                        self.text.index('SetEnvironmentVariableW'))


class BootstrapSummaryTests(unittest.TestCase):
    def test_last_helper_line_is_extracted_not_our_exit_marker(self):
        self.assertEqual(windows.bootstrap_summary(SAMPLE),
                         'LoadLibrary: The specified module could not be found.')

    def test_empty_child_output_yields_no_summary(self):
        silent = SAMPLE.replace("FATAL: Failed to load Python DLL 'python314.dll'.\n"
                                'LoadLibrary: The specified module could not be found.\n', '')
        self.assertEqual(windows.bootstrap_summary(silent), '')

    def test_absent_marker_yields_no_summary(self):
        self.assertEqual(windows.bootstrap_summary('unrelated text\n'), '')

    def test_older_entries_do_not_leak_into_the_latest_one(self):
        older = SAMPLE.replace('could not be found.', 'an earlier failure.')
        combined = older + '\n' + SAMPLE
        self.assertEqual(windows.bootstrap_summary(combined),
                         'LoadLibrary: The specified module could not be found.')


class HelperFailureAttributionTests(unittest.TestCase):
    def test_bootloader_exit_reports_the_captured_line(self):
        with patch.object(windows, 'bootstrap_diagnostic', return_value=SAMPLE):
            message = windows.helper_failure(1, 'before authorization readiness')
        self.assertIn('exited 1 before authorization readiness', message)
        self.assertIn('frozen helper failed before Python initialization', message)
        self.assertIn("bootloader: LoadLibrary: The specified module could not be found.", message)

    def test_bootloader_exit_without_output_still_names_the_log(self):
        with patch.object(windows, 'bootstrap_diagnostic', return_value=''), \
             patch.object(windows, 'bootstrap_log_path', return_value=r'C:\ProgramData\PYAS\Logs\policy-helper-bootstrap.log'):
            message = windows.helper_failure(1, 'before authorization readiness')
        self.assertIn('bootstrap log: ', message)
        self.assertIn('policy-helper-bootstrap.log', message)

    def test_other_exit_codes_stay_terminal_free(self):
        # Only exit 1 is the bootloader; every other code already has a reason.
        with patch.object(windows, 'bootstrap_diagnostic') as diagnostic:
            message = windows.helper_failure(5, 'before authorization readiness')
        self.assertEqual(diagnostic.call_count, 0)
        self.assertIn('did not receive an administrator token', message)

    def test_broker_exit_is_not_reported_as_a_bootloader_failure(self):
        # A bare 1 from the broker means the PowerShell host died before the
        # script reported a stage; calling that a bootloader failure sent the
        # investigation after Python entirely.
        with patch.object(windows, 'bootstrap_diagnostic') as diagnostic:
            message = windows.helper_failure(1, 'while waiting for the PowerShell broker')
        self.assertEqual(diagnostic.call_count, 0)
        self.assertIn('PowerShell broker exited before reporting a stage', message)
        self.assertNotIn('frozen helper failed', message)

    def test_broker_output_is_kept_not_discarded(self):
        # The broker once received PIPE handles and then hardcoded DEVNULL inside
        # Popen, so every PowerShell error vanished and exit codes were opaque.
        captured = {}

        class FakePopen:
            def __init__(self, *args, **kwargs): captured.update(kwargs)

        with patch.object(windows.subprocess, 'Popen', FakePopen):
            windows._run_broker('request', 'a' * 64,
                                 stdout=windows.subprocess.PIPE, stderr=windows.subprocess.PIPE)
        self.assertEqual(captured['stdout'], windows.subprocess.PIPE)
        self.assertEqual(captured['stderr'], windows.subprocess.PIPE)

    def test_unreadable_log_does_not_break_attribution(self):
        with patch.object(windows, 'bootstrap_log_path', return_value=''):
            self.assertEqual(windows.bootstrap_diagnostic(), '')
            message = windows.helper_failure(1, 'before authorization readiness')
        self.assertIn('frozen helper failed before Python initialization', message)

    def test_diagnostic_reads_the_tail_of_a_real_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'policy-helper-bootstrap.log')
            Path(path).write_text(SAMPLE, encoding='utf-8')
            with patch.object(windows, 'bootstrap_log_path', return_value=path):
                self.assertIn('could not be found', windows.bootstrap_diagnostic())

    def test_truncated_tail_still_parses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'policy-helper-bootstrap.log')
            Path(path).write_text(SAMPLE, encoding='utf-8')
            with patch.object(windows, 'bootstrap_log_path', return_value=path):
                tail = windows.bootstrap_diagnostic(limit=60)
        self.assertLess(len(tail), len(SAMPLE))
        self.assertTrue(tail)


if __name__ == '__main__': unittest.main()
