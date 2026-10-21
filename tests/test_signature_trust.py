"""Trusted signer validation without invoking PowerShell or native crypto."""
import ast
import base64
import hashlib
import json
import ntpath
import os
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from PYAS_Decisions import AlertPolicyMixin
ROOT = Path(__file__).resolve().parents[1]
tree = ast.parse((ROOT / "PYAS_Decisions.py").read_text(encoding="utf-8"))
fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "file_signer_hash")
scope = {"os": SimpleNamespace(name="nt", path=ntpath, environ={"SystemRoot": "C:/Windows"}), "json": json}
exec(compile(ast.Module(body=[fn], type_ignores=[]), "PYAS_Decisions.py", "exec"), scope)
verify = scope["file_signer_hash"]

class SignatureTrustTests(unittest.TestCase):
    def setUp(self):
        tool_root = patch("PYAS_FileTrust.system_directory", return_value="C:/Windows/System32")
        tool_root.start(); self.addCleanup(tool_root.stop)

    def test_only_valid_status_with_strict_thumbprint_is_accepted(self):
        for status in ("HashMismatch", "NotTrusted", "NotSigned", "UnknownError", None):
            with self.subTest(status=status):
                runner = Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps({"status": status, "thumbprint": "A" * 40})))
                self.assertIsNone(verify("fixture.exe", runner))
        good = Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps({"status": "Valid", "thumbprint": "a" * 40})))
        self.assertEqual(verify("fixture.exe", good), "A" * 40)

    def test_raw_hash_missing_fields_and_bad_process_results_fail_closed(self):
        for stdout, code in [("A" * 40, 0), ('{"thumbprint":"' + "A" * 40 + '"}', 0), ('[]', 0),
            ('{"status":"Valid","thumbprint":"bad"}', 0), (json.dumps({"status": "Valid", "thumbprint": "A" * 40}), 2)]:
            self.assertIsNone(verify("fixture.exe", Mock(return_value=SimpleNamespace(returncode=code, stdout=stdout))))

    def test_filename_is_data_and_command_checks_authenticode_status(self):
        path = "C:/fixture/'; Write-Output injected; #.exe"
        runner = Mock(return_value=SimpleNamespace(returncode=2, stdout=""))
        self.assertIsNone(verify(path, runner))
        command = runner.call_args.args[0]
        self.assertEqual(command[-2], "-EncodedCommand")
        script = base64.b64decode(command[-1]).decode("utf-16-le")
        self.assertIn("SignatureStatus]::Valid", script)
        self.assertNotIn(path, script)
        self.assertIn(base64.b64encode(path.encode()).decode(), script)

    def test_environment_cannot_redirect_the_signature_validator(self):
        scope['os'].environ['SystemRoot'] = 'C:/Untrusted'
        try:
            runner = Mock(return_value=SimpleNamespace(returncode=2, stdout=''))
            self.assertIsNone(verify('fixture.exe', runner))
            command = runner.call_args.args[0]
            self.assertEqual(command[0], ntpath.join('C:/Windows/System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'))
            self.assertNotIn('Untrusted', command[0])
        finally:
            scope['os'].environ['SystemRoot'] = 'C:/Windows'

    def test_untrusted_module_paths_and_clr_profiler_hooks_are_not_inherited(self):
        environment = scope['os'].environ
        original = dict(environment)
        environment.update({'PSModulePath': 'C:/Untrusted/Modules', 'COR_ENABLE_PROFILING': '1',
            'COR_PROFILER_PATH': 'C:/Untrusted/inject.dll', 'COMPLUS_Profiler': 'fixture', 'TEMP': 'C:/Temp'})
        try:
            runner = Mock(return_value=SimpleNamespace(returncode=2, stdout=''))
            self.assertIsNone(verify('fixture.exe', runner))
            options = runner.call_args.kwargs
            self.assertEqual(options['cwd'], 'C:/Windows/System32')
            self.assertEqual(options['env']['PSModulePath'], ntpath.join('C:/Windows/System32', 'WindowsPowerShell', 'v1.0', 'Modules'))
            for name in ('COR_ENABLE_PROFILING', 'COR_PROFILER_PATH', 'COMPLUS_Profiler'):
                self.assertNotIn(name, options['env'])
            self.assertEqual(options['env']['TEMP'], 'C:/Temp')
        finally:
            environment.clear(); environment.update(original)

    def test_cached_signer_is_bound_to_current_bytes(self):
        class Owner(AlertPolicyMixin): pass
        owner = Owner()
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "file.exe"
            file.write_bytes(b"first")
            digest = hashlib.sha256(b"first").hexdigest()
            rule = {"sha256": digest, "source": str(file)}
            with patch("PYAS_Decisions.file_signer_hash", return_value="A" * 40) as signer:
                self.assertEqual(owner._rule_signer(rule), "A" * 40)
                _retry_on_lock(lambda: file.write_bytes(b"changed"))
                self.assertIsNone(owner._rule_signer(rule))
                signer.assert_called_once()

def _retry_on_lock(action, attempts: int = 6, delay: float = 0.15):
    """重试一次被占用的文件操作。

    本机常驻杀软(含 PYAS 自己)会短暂持有 %TEMP% 下刚写入的文件,
    测试里一次写/读可能撞上 PermissionError。这不是被测逻辑的问题,
    重试几次即可;超过次数仍失败就是真错误,照常抛出。
    """
    import time as _time

    last = None
    for _ in range(attempts):
        try:
            return action()
        except PermissionError as error:   # 只重试"被占用",其它异常照常冒泡
            last = error
            _time.sleep(delay)
    raise last


if __name__ == "__main__": unittest.main()
