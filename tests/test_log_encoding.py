"""Real Windows PowerShell output and generated menu script regression checks."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

import build_menu
from PYAS_Encoding import decode_process_output


class LogEncodingTests(unittest.TestCase):
    def test_utf8_and_legacy_windows_output(self):
        message = '拒绝访问：中文路径 C:\\测试\\程序.exe'
        self.assertEqual(decode_process_output(message.encode('utf-8')), message)
        self.assertEqual(decode_process_output(message.encode('utf-8-sig')), message)
        # Only the ACP query is native; the decoder itself is platform-neutral.
        with patch('PYAS_Encoding.ctypes.windll', SimpleNamespace(kernel32=SimpleNamespace(GetACP=lambda: 936)), create=True), patch('PYAS_Encoding.os', SimpleNamespace(name='nt')):
            self.assertEqual(decode_process_output(message.encode('gbk')), message)
            self.assertNotIn('\ufffd', decode_process_output(b'\xff'))

    @unittest.skipUnless(os.name == 'nt', 'requires Windows PowerShell')
    def test_actual_powershell_chinese_stdout_stderr(self):
        result = build_menu.run_powershell("Write-Output '中文路径：测试'; [Console]::Error.WriteLine('拒绝访问：警告'); exit 7")
        self.assertEqual(result.returncode, 7)
        self.assertIn('中文路径：测试', result.stdout)
        self.assertIn('拒绝访问：警告', result.stderr)

    @unittest.skipUnless(os.name == 'nt', 'requires Windows PowerShell')
    def test_generated_defaults_resolve_after_param_without_registration(self):
        with tempfile.TemporaryDirectory(prefix='PYAS 中文菜单 ') as directory:
            root = Path(directory)
            with patch.object(build_menu, 'OUT', root):
                build_menu.write_scripts('3.7.0.4', 'PYAS_Menu_v3.7.0.4.msix')
            script = (root / 'register_menu.ps1').read_text(encoding='utf-8-sig')
            # Run the exact initialization; stop before any certificate/package operations.
            prefix = script.split('if ([Environment]::OSVersion')[0]
            probe = root / '初始化.ps1'
            probe.write_text(prefix + '\n[Console]::WriteLine($Msix); [Console]::Error.WriteLine($Cer)\n', encoding='utf-8-sig')
            result = subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                                     '-File', str(probe), '-ExternalLocation', str(root)], capture_output=True)
            self.assertEqual(result.returncode, 0, decode_process_output(result.stderr))
            self.assertEqual(result.stdout.decode('utf-8').strip(), str(root / 'PYAS_Menu_v3.7.0.4.msix'))
            self.assertEqual(result.stderr.decode('utf-8').strip(), str(root / 'menu_cert.cer'))


if __name__ == '__main__':
    unittest.main()
