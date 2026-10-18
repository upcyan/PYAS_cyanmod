"""Installation trust: accept a real Program Files install, reject user-writable copies.

Regression for the reported bug (no UAC prompt appeared). The evaluator used to treat
inherited "CREATOR OWNER:(OI)(CI)(IO)(F)" entries - which do NOT apply to the object
itself - as a write grant, so C:\\Program Files always failed the trust pre-check and
the request never reached elevation.

Observed real ACL of C:\\Program Files (Windows 11, trusted installer owned):
  ACE8  type=0 flags=0x0b mask=0x10000000  S-1-3-0     <- OI|CI|IO, children only
  ACE7  type=0 flags=0x0b mask=0xa0000000  S-1-5-32-545<- GENERIC_READ|EXECUTE
  ACE6  type=0 flags=0x00 mask=0x001200a9  S-1-5-32-545<- read+execute, no write
Both are safe; only INHERIT_ONLY handling and correct mask mapping are required.
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import PYAS_PolicyWindows as windows
except ImportError:  # pragma: no cover
    windows = None


class AceSemanticsTests(unittest.TestCase):
    """Pure mask/flag semantics: these run everywhere."""

    def setUp(self):
        if windows is None:
            self.skipTest('policy Windows module unavailable')

    def test_generic_all_and_generic_write_are_write(self):
        self.assertTrue(windows._ace_allows_write(0x10000000, True))
        self.assertTrue(windows._ace_allows_write(0x40000000, True))
        self.assertTrue(windows._ace_allows_write(0x1F01FF, True))

    def test_write_bits_are_write(self):
        for bit in (0x2, 0x4, 0x10, 0x100, 0x40000, 0x80000):
            self.assertTrue(windows._ace_allows_write(bit, True), hex(bit))

    def test_read_execute_only_is_not_write(self):
        # 0x1200A9 is what Program Files grants Users; 0xA0000000 is GENERIC_R|GENERIC_X.
        self.assertFalse(windows._ace_allows_write(0x1200A9, True))
        self.assertFalse(windows._ace_allows_write(0xA0000000, True))

    def test_delete_child_only_counts_on_containers(self):
        self.assertTrue(windows._ace_allows_write(0x40, True))
        self.assertFalse(windows._ace_allows_write(0x40, False))

    def test_inherit_only_flag_value(self):
        self.assertEqual(windows.ACE_INHERIT_ONLY, 0x08)
        self.assertEqual(windows.ACE_OBJECT_INHERIT, 0x01)
        self.assertEqual(windows.ACE_CONTAINER_INHERIT, 0x02)

    def test_broad_principals_are_untrusted(self):
        for sid in ('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-3-0'):
            self.assertIn(sid, windows.UNTRUSTED_SIDS)

    def test_administrators_and_trusted_installer_may_own(self):
        self.assertEqual(windows.ADMIN_SIDS, {'S-1-5-18', 'S-1-5-32-544'})
        self.assertIn(windows.TRUSTED_INSTALLER, windows.SYSTEM_OWNER_SIDS)
        self.assertNotIn(windows.TRUSTED_INSTALLER, windows.UNTRUSTED_SIDS)

    def test_every_rejection_path_records_a_stage(self):
        details = {}
        self.assertTrue(windows._dacl_grants_untrusted_write(None, True, details))
        self.assertEqual(details.get('stage'), 'dacl')
        self.assertIn('reason', details)

    def test_dacl_evaluator_binds_every_name_it_uses(self):
        # Guards a regression only Windows CI caught: a rewritten function header
        # left convert/kernel/advapi unbound, so every real path raised NameError.
        # Bytecode inspection runs on any platform.
        import dis
        function = windows._dacl_grants_untrusted_write
        code = function.__code__
        bound = set(code.co_varnames) | set(code.co_cellvars) | set(code.co_freevars)
        for name in ('convert', 'kernel', 'advapi', 'count', 'ace_fn', 'size'):
            self.assertIn(name, bound, name + ' must be bound inside the function')
        assigned = set(code.co_varnames[:code.co_argcount])
        for instruction in dis.get_instructions(function):
            if instruction.opname in ('STORE_FAST', 'STORE_DEREF'):
                assigned.add(instruction.argval)
            elif instruction.opname == 'LOAD_FAST':
                self.assertIn(instruction.argval, assigned,
                              instruction.argval + ' read before assignment')



@unittest.skipUnless(os.name == 'nt', 'requires Windows security descriptors')
class InstallationTrustTests(unittest.TestCase):
    def test_program_files_itself_is_accepted(self):
        program_files = os.environ.get('ProgramFiles', r'C:\Program Files')
        if not os.path.isdir(program_files):
            self.skipTest('no Program Files directory')
        details = {}
        self.assertTrue(
            windows.secure_path(program_files, directory=True, installation=True,
                                ancestor=True, details=details), details)
        self.assertIn(details.get('stage'), {'dacl-clean', 'verified'})

    def test_protected_system_binary_is_accepted(self):
        candidate = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'kernel32.dll'
        if not candidate.is_file():
            self.skipTest('kernel32.dll unavailable')
        details = {}
        self.assertTrue(windows.secure_path(candidate, installation=True, details=details), details)
        self.assertIn(details.get('stage'), {'dacl-clean', 'verified'})

    def test_normal_user_writable_directory_is_rejected_with_a_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            probe = Path(directory) / 'helper.exe'
            probe.write_bytes(b'fixture')
            # TEMP is often Administrators-only, which is genuinely safe; grant
            # Users modify explicitly so this asserts the rejection path.
            granted = subprocess.run(
                ['icacls', str(probe), '/grant', '*S-1-5-32-545:(M)'],
                capture_output=True, text=True)
            if granted.returncode != 0:
                self.skipTest('cannot grant Users modify: ' + granted.stderr.strip())
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
