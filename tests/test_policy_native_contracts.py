"""Policy native contracts with fake Win32 calls; no UAC/machine policy writes."""
import ast
import base64
import io
import os
from pathlib import Path
import struct
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import PYAS_PolicyWindows as windows
import PYAS_PolicyNative as native
from PYAS_Policy import PolicyDenied

class Channel(io.BytesIO):
    def close(self): self.final = self.getvalue(); super().close()

class NativeContractTests(unittest.TestCase):
    def lease(self):
        item = object.__new__(windows.WindowsPolicyLease)
        backend = SimpleNamespace(lock=threading.RLock(), leases=set())
        item.backend=backend; item.nonce='a'*32; item.path=os.path.join('/test','PolicyRequests',item.nonce+'.request')
        item.file=Channel(b'\0'*(windows.PAYLOAD_OFFSET+4));item.sent=False;item.closed=False
        item.native_process=None;item.launch_done=threading.Event();item.launch_error=None
        backend.leases.add(item)
        return item
    def test_cancel_before_commit_sends_abort_and_releases_channel(self):
        lease=self.lease()
        with patch.object(windows,'user_data_dir',return_value='/test'), patch.object(windows.os,'unlink') as remove:
            lease.close();lease.close()
        self.assertEqual(struct.unpack('<I',lease.file.final[windows.PAYLOAD_OFFSET:windows.PAYLOAD_OFFSET+4])[0],1)
        self.assertTrue(lease.file.closed);remove.assert_called_once()
    def test_close_after_commit_does_not_rewrite_it_as_cancelled(self):
        lease=self.lease();lease.sent=True
        with patch.object(windows,'user_data_dir',return_value='/test'),patch.object(windows.os,'unlink'):
            lease.close()
        self.assertEqual(lease.file.final[windows.PAYLOAD_OFFSET:windows.PAYLOAD_OFFSET+4],b'\0'*4)
    def test_late_shell_completion_releases_handle_after_cancel(self):
        lease=self.lease();lease.closed=True
        lease.digest='0'*64
        with patch.object(native,'elevate_helper',return_value=123),patch.object(windows,'_close') as close:
            lease._elevate()
        close.assert_called_once_with(123)
        self.assertIsNone(lease.native_process)
    def test_script_has_fixed_target_scoped_fields_cas_and_no_eval(self):
        script=base64.b64decode(windows._script('C:/Users/test/request','0'*64)).decode('utf-16-le')
        self.assertIn("'PYAS.Policy'",script)
        self.assertIn('CommonApplicationData',script)
        self.assertIn('$h.scope',script)
        self.assertIn('policy conflict',script)
        self.assertIn('AbandonedMutexException',script)
        self.assertNotIn('Invoke-Expression',script)
        self.assertNotIn('$h.target',script)
        self.assertNotIn('__ALL_KEYS__',script)
        self.assertLess(len(base64.b64encode(script.encode('utf-16-le'))),29000)
    def test_untrusted_installation_never_launches_helper(self):
        with patch.object(windows.sys,'executable','C:/Users/test/PYAS.exe'),patch('PYAS_DataPaths.known_folder',return_value='C:/Program Files'):
            self.assertFalse(windows.installed_helper_trusted())
    def test_script_size_is_bounded_before_any_native_call(self):
        with self.assertRaises(PolicyDenied): windows._script('x'*20000,'0'*64)

class WindowsParserTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='nt','requires Windows PowerShell parser')
    def test_broker_parses_without_execution(self):
        import subprocess
        directory,env=windows._environment()
        script=base64.b64decode(windows._script('C:/Users/test/request','0'*64)).decode('utf-16-le')
        raw=base64.b64encode(script.encode('utf-8')).decode()
        parser=("$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+raw+"'));"
          "$t=$null;$e=$null;[Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e)|Out-Null;"
          "if($e.Count){$e|ForEach-Object{$_.Message};exit 1}")
        result=subprocess.run([os.path.join(directory,'WindowsPowerShell','v1.0','powershell.exe'),'-NoProfile','-NonInteractive',
          '-EncodedCommand',base64.b64encode(parser.encode('utf-16-le')).decode()],env=env,capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

class HelperFailureTests(unittest.TestCase):
    def test_helper_preserves_verification_and_broker_launch_stages(self):
        for failing_stage, expected in (('verify', 11), ('launch', 0x20000)):
            with self.subTest(stage=failing_stage), patch.object(windows.os, 'name', 'nt'), \
                 patch.object(windows.sys, 'frozen', True, create=True), \
                 patch.object(native, 'verify_request_owner',
                     side_effect=PolicyDenied('request rejected') if failing_stage == 'verify' else None,
                     return_value=[123]), \
                 patch.object(windows, '_run_broker', side_effect=OSError('launch failed')), \
                 patch.object(windows, '_close') as close:
                self.assertEqual(windows.helper_main(['request', 'a' * 64]), expected)
                self.assertEqual(close.call_count, int(failing_stage == 'launch'))

    def test_native_verification_winerror_is_preserved(self):
        error = OSError('access denied')
        error.winerror = 5
        with patch.object(windows.os, 'name', 'nt'), \
             patch.object(windows.sys, 'frozen', True, create=True), \
             patch.object(native, 'verify_request_owner', side_effect=error), \
             patch.object(windows, 'write_helper_log') as record:
            self.assertEqual(windows.helper_main(['request', 'a' * 64]), 0x10005)
            self.assertEqual(record.call_count, 1)  # the finally-block log covers every failure path
        self.assertIn('WinError 5', windows.helper_failure(0x10005, 'before readiness'))

    def test_policy_denied_reasons_map_to_fixed_exit_codes(self):
        cases = {'Untrusted helper installation': 13, 'Request owner is not this application': 14,
                 'Request hash mismatch': 15, 'Invalid request identity': 15,
                 'Invalid request location': 15, 'Invalid request owner': 15,
                 'Request is not owned by the GUI': 16, 'Request file was replaced': 16,
                 'Request sharing mode is invalid': 16,
                 'Request is not exclusively writable by the GUI': 16,
                 'Local fixed-drive request required': 17,
                 'Remote policy requests are not supported': 17,
                 'Reparse-point policy requests are not supported': 17,
                 'Local request required': 17}
        for message, expected in cases.items():
            with self.subTest(message=message), \
                 patch.object(windows.os, 'name', 'nt'), \
                 patch.object(windows.sys, 'frozen', True, create=True), \
                 patch.object(native, 'verify_request_owner', side_effect=PolicyDenied(message)), \
                 patch.object(windows, 'write_helper_log'):
                self.assertEqual(windows.helper_main(['request', 'a' * 64]), expected, message)

    def test_helper_preserves_broker_exit_stage_and_releases_pinned_handles(self):
        process = Mock()
        process.wait.return_value = 45
        with patch.object(windows.os, 'name', 'nt'), \
             patch.object(windows.sys, 'frozen', True, create=True), \
             patch.object(native, 'verify_request_owner', return_value=[123, 456]), \
             patch.object(windows, '_run_broker', return_value=process), \
             patch.object(windows, '_close') as close:
            self.assertEqual(windows.helper_main(['request', 'a' * 64]), 45)
            self.assertEqual([c.args[0] for c in close.call_args_list], [456, 123])
        self.assertIn('receipt creation', windows.helper_failure(45, 'before readiness'))
        self.assertIn('exited 45', windows.helper_failure(45, 'before readiness'))

if __name__=='__main__':unittest.main()
