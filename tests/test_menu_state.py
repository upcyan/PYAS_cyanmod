"""Persist failed menu attempts and test the production registration boundary."""
import ast
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from PYAS_Encoding import decode_process_output
from PYAS_MenuState import MenuRegistrationState

tree = ast.parse((Path(__file__).resolve().parents[1] / 'PYAS.py').read_text(encoding='utf-8'))
owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == '_MainMixin')
names = {'register_modern_context_menu', 'get_context_menu_status'}
system = SimpleNamespace(frozen=True, getwindowsversion=lambda: SimpleNamespace(build=22621))
scope = dict(os=os, sys=system, subprocess=subprocess, MenuRegistrationState=MenuRegistrationState,
             decode_process_output=decode_process_output, log_exception=Mock())
exec(compile(ast.Module(body=[n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[]), 'PYAS.py', 'exec'), scope)
MenuAPI = type('MenuAPI', (), {name: scope[name] for name in names})


class MenuStateTests(unittest.TestCase):
    def setUp(self):
        # Native calls are mocked; provide only the missing SDK constant on Linux.
        sdk = patch.object(subprocess, 'CREATE_NO_WINDOW', 0, create=True)
        sdk.start(); self.addCleanup(sdk.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        menu = self.root / 'Menu'
        menu.mkdir()
        for name in ['register_menu.ps1', 'unregister_menu.ps1', 'menu_cert.cer', 'test.msix']:
            (menu / name).write_bytes(b'fixture')
        self.environment = patch.dict(os.environ, LOCALAPPDATA=str(self.root / 'user'))
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.process = patch.object(subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b'', stderr='证书不受信任 0x800B0109'.encode('utf-8')))
        self.run = self.process.start()
        self.addCleanup(self.process.stop)

    def api(self):
        api = MenuAPI()
        api.path_pyas = str(self.root)
        api.path_system = r'C:\Windows'
        api.write_log = Mock()
        api._context_menu_mode = 'legacy'
        return api

    def test_failed_package_is_not_retried_across_processes(self):
        self.assertFalse(self.api().register_modern_context_menu(True))
        second = self.api()
        self.assertFalse(second.register_modern_context_menu(True))
        self.assertTrue(second._menu_attempt_skipped)
        self.assertEqual(self.run.call_count, 1)
        second.write_log.assert_not_called()

    def test_first_failure_notice_contains_reason_and_is_consumed_once(self):
        api = self.api()
        api.register_modern_context_menu(True)
        self.assertIn('0x800B0109', api.get_context_menu_status()['notice'])
        self.assertEqual(api.get_context_menu_status()['notice'], '')
        second = self.api()
        second.register_modern_context_menu(True)
        self.assertEqual(second.get_context_menu_status(), {'mode': 'legacy', 'notice': ''})

    def test_manual_retry_is_allowed_without_repeating_initial_notice(self):
        api = self.api()
        api.register_modern_context_menu(True)
        api.get_context_menu_status()
        api.register_modern_context_menu(True, retry=True)
        self.assertEqual(self.run.call_count, 2)
        self.assertEqual(api.get_context_menu_status()['notice'], '')

    def test_package_change_allows_one_new_attempt(self):
        self.api().register_modern_context_menu(True)
        (self.root / 'Menu' / 'test.msix').write_bytes(b'updated package')
        api = self.api()
        api.register_modern_context_menu(True)
        self.assertEqual(self.run.call_count, 2)
        self.assertIn('0x800B0109', api.get_context_menu_status()['notice'])

    def test_disable_is_never_skipped_and_success_clears_failure(self):
        api = self.api()
        api.register_modern_context_menu(True)
        self.run.return_value = SimpleNamespace(returncode=0, stdout=b'ok', stderr=b'')
        self.assertTrue(api.register_modern_context_menu(False))
        self.assertEqual(self.run.call_count, 2)
        self.assertFalse(MenuRegistrationState(str(self.root)).failed())
        self.assertEqual(api.get_context_menu_status()['notice'], '')

    def test_classic_menu_setting_reports_displayed_original_mode(self):
        api = self.api()
        api._context_menu_mode = 'modern'
        api.pyas_config = {'classic_menu_switch': True}
        self.assertEqual(api.get_context_menu_status()['mode'], 'legacy')
        api.pyas_config['classic_menu_switch'] = False
        self.assertEqual(api.get_context_menu_status()['mode'], 'modern')


if __name__ == '__main__':
    unittest.main()
