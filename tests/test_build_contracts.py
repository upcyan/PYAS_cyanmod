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
        with patch.object(build, 'run', side_effect=[SimpleNamespace(returncode=0),SimpleNamespace(returncode=1)]) as run:
            with self.assertRaises(SystemExit): build.run_build_contracts(('one.py','bad.py','never.py'))
            self.assertEqual(run.call_count,2)

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
