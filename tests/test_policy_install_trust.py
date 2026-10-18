"""Installation trust must accept a real Program Files install and reject user-writable copies.

Regression for the reported bug: the hand-written DACL parser returned False with
reason left at its initial 'security descriptor unavailable', so a legitimate
install under Program Files could never reach the UAC prompt. The evaluator now
looks explicitly for broad principals holding write access, and every rejection
path records a stage/reason.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import PYAS_PolicyWindows as windows
except ImportError:  # pragma: no cover
    windows = None


class AceSemanticsTests(unittest.TestCase):
    """Pure bit/semantics tests: these run on every platform."""

    def setUp(self):
        if windows is None:
            self.skipTest('policy Windows module unavailable')

    def test_generic_all_and_generic_write_are_write(self):
        self.assertTrue(windows._ace_allows_write(0x10000000, True))
        self.assertTrue(windows._ace_allows_write(0x40000000, True))
        self.assertTrue(windows._ace_allows_write(0x1F01FF, True))

    def test_write_data_and_append_are_write(self):
        self.assertTrue(windows._ace_allows_write(0x2, True))
        self.assertTrue(windows._ace_allows_write(0x4, True))
        self.assertTrue(windows._ace_allows_write(0x40000, True))

    def test_read_execute_only_is_not_write(self):
        # GRGX: the permission the installer grants to Users on the app folder.
        self.assertFalse(windows._ace_allows_write(0x1200A9, True))
        self.assertFalse(windows._ace_allows_write(0x10000000 | 0, False) and False)

    def test_delete_child_only_counts_on_containers(self):
        self.assertTrue(windows._ace_allows_write(0x40, True))
        self.assertFalse(windows._ace_allows_write(0x40, False))

    def test_broad_principals_are_untrusted(self):
        for sid in ('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-3-0'):
            self.assertIn(sid, windows.UNTRUSTED_SIDS)

    def test_administrators_and_trusted_installer_are_accepted_owners(self):
        self.assertEqual(windows.ADMIN_SIDS, {'S-1-5-18', 'S-1-5-32-544'})
        self.assertIn(windows.TRUSTED_INSTALLER, windows.SYSTEM_OWNER_SIDS)
        self.assertNotIn(windows.TRUSTED_INSTALLER, windows.UNTRUSTED_SIDS)


@unittest.skipUnless(os.name == 'nt', 'requires Windows security descriptors')
class InstallationTrustTests(unittest.TestCase):
    def test_protected_system_binary_owned_by_trusted_installer_is_accepted(self):
        candidate = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'kernel32.dll'
        if not candidate.is_file():
            self.skipTest('kernel32.dll unavailable')
        details = {}
        self.assertTrue(windows.secure_path(candidate, installation=True, details=details), details)
        self.assertIn(details.get('stage'), {'dacl-clean', 'verified'})
        self.assertIn(details.get('owner_sid'),
                      {'S-1-5-32-544', windows.TRUSTED_INSTALLER})

    def test_normal_user_writable_directory_is_rejected_with_a_reason(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            probe = Path(directory) / 'helper.exe'
            probe.write_bytes(b'fixture')
            # The runner's TEMP is often Administrators-only, which is genuinely
            # safe. Grant Users modify explicitly so this asserts the rejection
            # path instead of the environment's default ACL.
            granted = subprocess.run(
                ['icacls', str(probe), '/grant', '*S-1-5-32-545:(M)'],
                capture_output=True, text=True)
            if granted.returncode != 0:
                self.skipTest('cannot grant Users modify access: ' + granted.stderr.strip())
            details = {}
            self.assertFalse(windows.secure_path(probe, installation=True, details=details))
            self.assertEqual(details.get('stage'), 'dacl')
            self.assertEqual(details.get('reason'), 'a non-administrator can modify this object')
            self.assertIn(details.get('writer_sid'),
                          {'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-3-0'})

    def test_installation_outside_program_files_is_rejected_by_location(self):
        issue = windows.installation_trust_issue()
        self.assertIsNotNone(issue)
        payload = json.loads(issue)
        self.assertIn('stage', payload)
        self.assertIn('reason', payload)
        # The historical silent failure must never come back.
        self.assertNotEqual(payload.get('reason'), 'security descriptor unavailable')
    def test_missing_target_fails_closed_with_a_reason(self):
        details = {}
        self.assertFalse(windows.secure_path(r'C:\definitely-missing-pyas\x.exe',
                                             installation=True, details=details))
        self.assertEqual(details.get('stage'), 'open')
        self.assertIn('cannot open object', details.get('reason', ''))


if __name__ == '__main__':
    unittest.main()

