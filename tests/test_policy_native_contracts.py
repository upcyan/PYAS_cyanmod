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
        # Machine scope must come from the registry: in the minimal environment
        # the helper hands PowerShell, GetFolderPath('CommonApplicationData')
        # returns '' and Join-Path throws before any stage is recorded.
        self.assertIn("GetEnvironmentVariable('ProgramData','Machine')",script)
        self.assertNotIn('GetFolderPath',script)
        # $stage must exist before the first statement that can throw, otherwise
        # the catch block exits with $null (a bare 1) and hides the real stage.
        head = script.split('try{')[0]
        self.assertIn('$stage=40', head)
        self.assertLess(head.index('$stage=40'), head.index('$programData='))
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
        # Parse from a .ps1 file: nesting the whole broker inside another
        # -EncodedCommand doubled its size and hit WinError 206 (command line too
        # long), which says nothing about the script itself.
        import subprocess
        import tempfile
        directory,env=windows._environment()
        script=base64.b64decode(windows._script('C:/Users/test/request','0'*64)).decode('utf-16-le')
        with tempfile.TemporaryDirectory() as workspace:
            path=os.path.join(workspace,'parse.ps1')
            with open(path,'w',encoding='utf-8-sig') as stream: stream.write(script)
            parser=("$t=$null;$e=$null;"
              "[Management.Automation.Language.Parser]::ParseFile('"+path.replace("'","''")+"',[ref]$t,[ref]$e)|Out-Null;"
              "if($e.Count){$e|ForEach-Object{$_.Message};exit 1}")
            result=subprocess.run([os.path.join(directory,'WindowsPowerShell','v1.0','powershell.exe'),
              '-NoProfile','-NonInteractive','-Command',parser],env=env,capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_broker_replacement_uses_a_real_null_backup_and_retries(self):
        """替换策略文件时第三个参数必须写 [NullString]::Value,不能写 $null。

        脚本宿主会把 $null 绑成空字符串,File.Replace 判为非法参数(E_INVALIDARG)
        直接抛 —— 2026-10-19 白名单移除每次都在这里失败:初始化走 Move 分支所以没事,
        任何一次「更新」都必然失败,失败的 .config-*.tmp 还留在策略目录里。
        一并锁住:共享冲突的重试、回读确认(1177:已落地但旧文件删不掉)、失败清理。
        """
        text = windows.BROKER
        self.assertIn('[IO.File]::Replace($temporary,$target,[NullString]::Value)', text)
        self.assertNotIn('Replace($temporary,$target,$null)', text)
        self.assertIn('for($attempt=1;$attempt -le 8;$attempt++)', text)
        self.assertIn('$done=($check._request -ceq $nonce)', text)
        self.assertIn("[Console]::Error.WriteLine('policy replace failed '+$failed)", text)
        self.assertIn('[IO.File]::Delete($temporary)', text)

    def test_commit_failure_surfaces_the_broker_win32_code(self):
        """退出码只说「替换失败」,真正的 Win32 码在 broker 的 stderr 里(helper 日志)。

        共享冲突(0x80070020)和权限问题(0x80070005)要能分开,否则线上只能猜。
        """
        item = object.__new__(windows.WindowsPolicyLease)
        item.path = os.path.join('/test', 'PolicyRequests', 'a' * 32 + '.request')
        log = ('exit=49 phase=while waiting for the policy broker seconds=1.8 '
               'stderr: policy replace failed win32=0x80070020 hresult=0x80131501 attempt=8')
        with patch.object(windows, 'read_helper_log', return_value=log):
            message = item._denied(49, 'during policy commit')
        self.assertIn('atomic policy replacement failed', message)
        self.assertIn('(win32=0x80070020)', message)

    def test_commit_failure_without_diagnostic_stays_short(self):
        item = object.__new__(windows.WindowsPolicyLease)
        item.path = os.path.join('/test', 'PolicyRequests', 'a' * 32 + '.request')
        with patch.object(windows, 'read_helper_log', return_value='exit=49 phase=x'):
            message = item._denied(49, 'during policy commit')
        self.assertNotIn('win32=', message)

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
        # The helper drains both pipes through communicate(); waiting first would
        # deadlock once the broker fills the pipe buffer.
        process.communicate.return_value = (b'', b'')
        process.returncode = 45
        with patch.object(windows.os, 'name', 'nt'), \
             patch.object(windows.sys, 'frozen', True, create=True), \
             patch.object(native, 'verify_request_owner', return_value=[123, 456]), \
             patch.object(windows, '_run_broker', return_value=process), \
             patch.object(windows, '_close') as close:
            self.assertEqual(windows.helper_main(['request', 'a' * 64]), 45)
            self.assertEqual([c.args[0] for c in close.call_args_list], [456, 123])
    @unittest.skipUnless(os.name == 'nt', 'requires Windows ctypes')

    def test_elevation_routes_through_the_static_launcher(self):
        # Regression for 'exited 1 before Python initialization': the runas child
        # inherited the GUI's PyInstaller _PYI_* environment and the bootloader
        # aborted. Elevation must start the static launcher instead of PYAS.exe.
        captured = {}

        class Info:
            hProcess = None
            lpFile = None
            lpParameters = None
            lpVerb = None

        holder = Info()

        class Function:
            argtypes = None
            restype = None
            def __call__(self, pointer):
                # A real ShellExecuteExW writes the process handle back into the
                # structure; the fake must do the same on the byref target.
                pointer.hProcess = 4321
                captured.update(file=pointer.lpFile, parameters=pointer.lpParameters,
                                verb=pointer.lpVerb)
                return True

        class Shell:
            ShellExecuteExW = Function()

        # ctypes.sizeof is not mocked: Python 3.14 evaluates it while laying out
        # nested structures, so replacing it breaks the class body itself. The
        # real SHELLEXECUTEINFO size is already what the call sets.
        with patch.object(native, 'launcher_path', return_value='C:/Program Files/PYAS/PYAS_Launcher.exe'), \
             patch.object(native.ctypes, 'WinDLL', return_value=Shell()), \
             patch.object(native.ctypes, 'byref', side_effect=lambda value: value):
            handle = native.elevate_helper('request', 'a' * 64)
        self.assertEqual(handle, 4321)
        self.assertEqual(captured['file'], 'C:/Program Files/PYAS/PYAS_Launcher.exe')
        self.assertEqual(captured['verb'], 'runas')
        self.assertIn('--pyas-policy-helper', captured['parameters'])
        self.assertIn('--wait', captured['parameters'])

    def test_launcher_path_rejects_missing_component(self):
        with patch.object(native.os.path, 'isfile', side_effect=lambda p: 'PYAS_Launcher' not in p):
            with self.assertRaises(PolicyDenied):
                native.launcher_path()


if __name__=='__main__':unittest.main()


if __name__=='__main__':unittest.main()
