"""EICAR self-test support: detection must work for the marker, and only it.

The marker is a published, harmless 68-byte string. Two things have to hold:
the rule matches it, and the realtime suffix filter does not hide it. The second
one is what made a .txt EICAR invisible before: .txt is not in the suffix list.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest


def _pyas_running():
    """本机 PYAS 在跑时,EICAR 用例会被当成真威胁:每写一个文件弹一次拦截窗。

    这是防护正常工作,不是测试失败。跳过的代价只是本地构建不校验这条规则,
    CI 上没有 PYAS 进程,照常执行。
    """
    try:
        result = subprocess.run(["tasklist", "/FI", "IMAGENAME eq PYAS.exe", "/NH"],
                                capture_output=True, text=True, errors="replace", timeout=10)
    except OSError:
        return False
    return "PYAS.exe" in result.stdout


PYAS_RUNNING = _pyas_running()
PYAS_SKIP = "PYAS 正在运行:它会拦截测试写入的 EICAR 文件(每跑一次弹一次告警窗)"
from unittest.mock import patch

import PYAS_Realtime as realtime

ROOT = Path(__file__).resolve().parents[1]
EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


class _Workspace(unittest.TestCase):
    def setUp(self):
        # EICAR 是真杀软测试串:本机 PYAS 正在运行时会短暂持有它(实测 WinError 32),
        # 清理失败不该把构建门禁判红
        self.workspace = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.workspace.cleanup)

    def write(self, name, data):
        path = Path(self.workspace.name) / name
        path.write_bytes(data)
        return str(path)


@unittest.skipIf(PYAS_RUNNING, PYAS_SKIP)
class EicarProbeTests(_Workspace):
    def test_marker_is_recognised_whatever_the_extension(self):
        for name in ('eicar.txt', 'eicar.log', 'no-extension', 'eicar.docm'):
            with self.subTest(name=name):
                self.assertTrue(realtime.looks_like_eicar(self.write(name, EICAR + b'\r\n')))

    def test_marker_inside_larger_text_is_still_recognised(self):
        path = self.write('notes.txt', b'line one\n' + EICAR + b'\nline two\n')
        self.assertTrue(realtime.looks_like_eicar(path))

    def test_ordinary_text_is_not_mistaken_for_the_marker(self):
        self.assertFalse(realtime.looks_like_eicar(self.write('plain.txt', b'hello, ordinary file\n')))

    def test_half_of_the_marker_is_not_enough(self):
        # Guards the probe against matching on the short head alone.
        self.assertFalse(realtime.looks_like_eicar(self.write('half.txt', realtime.EICAR_HEAD)))

    def test_oversized_file_is_not_probed(self):
        path = self.write('big.txt', b'A' * (realtime.EICAR_PROBE_BYTES + 1) + EICAR)
        self.assertFalse(realtime.looks_like_eicar(path))

    def test_missing_or_unreadable_file_fails_closed(self):
        self.assertFalse(realtime.looks_like_eicar(str(Path(self.workspace.name) / 'nope.txt')))
        with patch.object(realtime.os.path, 'getsize', side_effect=OSError('denied')):
            self.assertFalse(realtime.looks_like_eicar('anything'))

    def test_the_module_does_not_contain_the_marker_in_one_piece(self):
        # Otherwise the probe would flag PYAS's own source during a file scan.
        source = (ROOT / 'PYAS_Realtime.py').read_bytes()
        self.assertNotIn(EICAR, source)
        self.assertIn(realtime.EICAR_HEAD, source)
        self.assertIn(realtime.EICAR_TAIL, source)


@unittest.skipIf(PYAS_RUNNING, PYAS_SKIP)
class SuffixGateTests(_Workspace):
    def test_unfiltered_mode_accepts_every_suffix(self):
        self.assertTrue(realtime.file_needs_scan('anything.png', False, []))

    def test_listed_suffix_is_scanned(self):
        self.assertTrue(realtime.file_needs_scan('payload.exe', True, ['.exe']))

    def test_unlisted_suffix_is_skipped_when_it_is_not_the_marker(self):
        # .txt 不在默认后缀表里:普通文本不该因此被拉进扫描
        path = self.write('plain.txt', b'ordinary text\n')
        self.assertFalse(realtime.file_needs_scan(path, True, ['.exe']))

    def test_marker_overrides_the_suffix_filter(self):
        path = self.write('eicar.txt', EICAR + b'\n')
        self.assertTrue(realtime.file_needs_scan(path, True, ['.exe']))


class EicarRuleTests(unittest.TestCase):
    RULE = ROOT / 'Engine' / 'Heuristic' / 'Rules_SelfTest.yar'

    def test_rule_matches_the_marker_and_not_its_own_source(self):
        import yara
        rules = yara.compile(filepath=str(self.RULE))
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as workspace:
            cases = {'eicar.txt': (EICAR + b'\n', True),
                     'notes.txt': (b'before\n' + EICAR + b'\nafter\n', True),
                     'plain.txt': (b'ordinary\n', False),
                     'rule.yar': (self.RULE.read_bytes(), False)}
            for name, (data, expected) in cases.items():
                path = Path(workspace) / name
                path.write_bytes(data)
                with self.subTest(name=name):
                    self.assertEqual(bool(rules.match(str(path))), expected)

    def test_rule_declares_itself_as_a_self_test(self):
        text = self.RULE.read_text(encoding='utf-8')
        self.assertIn('severity = "test"', text)
        self.assertIn('not malware', text)
        # The marker must stay hex here: an ASCII copy would self-match.
        self.assertNotIn('EICAR-STANDARD-ANTIVIRUS-TEST-FILE!', text)


if __name__ == '__main__':
    unittest.main()
