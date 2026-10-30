"""Exercise actual menu registration logic without changing Explorer/registry."""
import ast
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, MagicMock


tree = ast.parse((Path(__file__).resolve().parents[1] / 'PYAS.py').read_text(encoding='utf-8'))
owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == '_MainMixin')
method = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'register_context_menu')
system = SimpleNamespace(frozen=True, getwindowsversion=lambda: SimpleNamespace(build=22621))
registry = SimpleNamespace(HKEY_CURRENT_USER=1, REG_SZ=1, KEY_READ=1, OpenKey=MagicMock())
scope = {'sys': system, 'winreg': registry, 'log_exception': Mock(),
        '_LT': __import__('PYAS_LogTexts', fromlist=['LOG_TEXTS']).LOG_TEXTS}
exec(compile(ast.Module(body=[method], type_ignores=[]), 'PYAS.py', 'exec'), scope)
MenuAPI = type('MenuAPI', (), {'register_context_menu': scope['register_context_menu']})


class ContextMenuTests(unittest.TestCase):
    def api(self, legacy=True, modern=True, build=22621):
        system.getwindowsversion = lambda: SimpleNamespace(build=build)
        system.frozen = True
        api = MenuAPI()
        api.file_pyas = r'C:\Program Files\PYAS\PYAS.exe'
        api.python = r'C:\Python\python.exe'
        api._reg_write = Mock(return_value=legacy)
        api._reg_delete = Mock(return_value=legacy)
        api.register_modern_context_menu = Mock(return_value=modern)
        api.write_log = Mock()
        api._loc = Mock(return_value='menu')
        return api

    def test_modern_failure_keeps_original_scan_commands_and_reports_fallback(self):
        api = self.api(modern=False)
        self.assertTrue(api.register_context_menu(True))
        commands = [call.args for call in api._reg_write.call_args_list if call.args[1].endswith('\\command')]
        self.assertEqual(len(commands), 2, 'file and directory scan commands must both be installed')
        self.assertTrue(all(args[-1] == '"C:\\Program Files\\PYAS\\PYAS.exe" -scan "%1"' for args in commands))
        api.register_modern_context_menu.assert_called_once_with(True, retry=False)
        self.assertTrue(any(call.args[1] == 'Context Menu Fallback' for call in api.write_log.call_args_list))

    def test_both_modes_fail_returns_failure(self):
        self.assertFalse(self.api(legacy=False, modern=False).register_context_menu(True))

    def test_modern_success_is_sufficient_on_windows11(self):
        self.assertTrue(self.api(legacy=False).register_context_menu(True))

    def test_noop_modern_on_windows10_does_not_mask_original_failure(self):
        self.assertFalse(self.api(legacy=False, build=19045).register_context_menu(True))

    def test_source_mode_requires_original_menu(self):
        api = self.api(legacy=False)
        system.frozen = False
        self.assertFalse(api.register_context_menu(True))

    def test_disable_requires_removing_both_modes(self):
        for legacy, modern in [(False, True), (True, False), (False, False), (True, True)]:
            api = self.api(legacy=legacy, modern=modern)
            self.assertEqual(api.register_context_menu(False), legacy and modern)
            self.assertEqual(api._reg_delete.call_count, 4)
            api.register_modern_context_menu.assert_called_once_with(False, retry=False)


if __name__ == '__main__':
    unittest.main()
