"""Build gates remain mandatory regardless of workflow credentials."""
from contextlib import ExitStack
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
import build

class BuildContractTests(unittest.TestCase):
    def test_each_named_contract_is_run_and_failures_stop_the_build(self):
        with patch.object(build, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            build.run_build_contracts(('one.py','two.py'))
            self.assertEqual([call.args[0][-2:] for call in run.call_args_list],[['one.py','-v'],['two.py','-v']])
        # 失败会给一次重试(本机杀软会短暂锁住 %TEMP% 里的文件),所以第二次失败要准备第三份结果
        with patch.object(build, 'run', side_effect=[SimpleNamespace(returncode=0),
                                                     SimpleNamespace(returncode=1),
                                                     SimpleNamespace(returncode=1)]) as run:
            with self.assertRaises(SystemExit): build.run_build_contracts(('one.py','bad.py','never.py'))
            self.assertEqual(run.call_count,3, '失败后应重试一次,仍失败才中断构建')
            self.assertEqual([call.args[0][-2:] for call in run.call_args_list],
                             [['one.py','-v'],['bad.py','-v'],['bad.py','-v']],
                             '重试的必须还是同一个 pattern,且 never.py 不应被执行')

    def test_iss_keeps_utf8_bom_after_version_sync(self):
        """Inno 脚本必须是带 BOM 的 UTF-8:否则中文注释按 ANSI 解码,
        某些双字节字符尾字节是 0x7D('}'),会把 { } 注释提前闭合 -> Invalid section tag。"""
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'X.iss'
            target.write_bytes(b'\xef\xbb\xbf#define AppVersion "1.0"\r\n[Setup]\r\n')
            original = build.ISS_FILE
            build.ISS_FILE = target
            try:
                build.sync_iss_version('3.7.1-17')
            finally:
                build.ISS_FILE = original

            data = target.read_bytes()
            self.assertTrue(data.startswith(b'\xef\xbb\xbf'), '版本同步后必须保留 UTF-8 BOM')
            self.assertIn(b'#define AppVersion "3.7.1.17"', data)

    def test_pyas_never_uses_undefined_logger(self):
        """PYAS.py 里的 `logger` 只在 main() 作用域内定义过。

        方法里随手写 `logger.info(...)` 会 NameError —— 而它常常发生在
        wndproc / js_api 这类"被异常兜底包起来"的路径上,表现为某个功能点了没反应,
        日志里只留一条 pywebview 的 traceback。
        """
        import ast
        from pathlib import Path
        source = Path(build.__file__).with_name('PYAS.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        offenders = []

        class Visitor(ast.NodeVisitor):
            """沿调用链继承"外层是否定义过 logger"(main() 里定义,nested def 可以用)。"""

            def __init__(self):
                self.has_logger = False

            def visit_FunctionDef(self, node):
                assigned = {n.id for n in ast.walk(node)
                            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
                assigned |= {a.arg for a in node.args.args}

                if not self.has_logger and 'logger' not in assigned:
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Name) and sub.id == 'logger' and isinstance(sub.ctx, ast.Load):
                            offenders.append((node.name, sub.lineno))

                previous, self.has_logger = self.has_logger, self.has_logger or 'logger' in assigned
                self.generic_visit(node)
                self.has_logger = previous

        Visitor().visit(tree)
        self.assertEqual(offenders, [], f'这些位置用了未定义的 logger: {offenders}')

    def mocked_build(self, gates):
        stack=ExitStack(); self.addCleanup(stack.close)
        for name in ('lint_i18n','write_build_channel','sync_iss_version','check_python_packages','check_inno_languages','ensure_redist','ensure_setup_resources','assemble_payload'):
            stack.enter_context(patch.object(build,name))
        stack.enter_context(patch.object(build,'read_version',return_value='3.7.1-10'))
        stack.enter_context(patch.object(build,'find_iscc',return_value='ISCC.exe'))
        stack.enter_context(patch.object(build,'run_build_contracts',side_effect=gates))
        menu=stack.enter_context(patch.object(build,'run',return_value=SimpleNamespace(returncode=0)))
        exe=stack.enter_context(patch.object(build,'build_exe'))
        iscc=stack.enter_context(patch.object(build,'run_iscc',return_value='installer.exe'))
        return menu,exe,iscc

    def test_preflight_and_certificate_checks_surround_packaging(self):
        events=[]
        menu,exe,iscc=self.mocked_build(lambda patterns:events.append(tuple(patterns)))
        exe.side_effect=lambda:events.append('exe')
        menu.side_effect=lambda command:events.append('launcher' if command[-1].endswith('build_launcher.py') else 'menu') or SimpleNamespace(returncode=0)
        iscc.side_effect=lambda *args:events.append('installer') or 'installer.exe'
        self.assertEqual(build.do_build(False,'normal'),'installer.exe')
        self.assertEqual(events,[build.BUILD_CONTRACT_PATTERNS,'exe','launcher','menu',('test_menu_certificate.py',),'installer'])

    def test_preflight_failure_cannot_produce_an_executable(self):
        menu,exe,iscc=self.mocked_build(Mock(side_effect=SystemExit(1)))
        with self.assertRaises(SystemExit):build.do_build(False,'normal')
        exe.assert_not_called();menu.assert_not_called();iscc.assert_not_called()

    def test_launcher_or_frozen_probe_failure_cannot_produce_an_installer(self):
        menu,exe,iscc=self.mocked_build(lambda patterns:None)
        menu.return_value=SimpleNamespace(returncode=1)
        with self.assertRaises(SystemExit):build.do_build(False,'normal')
        exe.assert_called_once();menu.assert_called_once();iscc.assert_not_called()

    def test_certificate_failure_cannot_produce_an_installer(self):
        menu,exe,iscc=self.mocked_build(Mock(side_effect=[None,SystemExit(1)]))
        with self.assertRaises(SystemExit):build.do_build(False,'normal')
        exe.assert_called_once();self.assertEqual(menu.call_count,2);iscc.assert_not_called()

if __name__=='__main__':unittest.main()
