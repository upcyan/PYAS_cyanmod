"""Check automatic menu trust scope without loading protection engines."""
import ast
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock
from PYAS_ComponentTrust import component_digest, is_menu_component_copy

root = Path(__file__).resolve().parents[1]
tree = ast.parse((root / 'PYAS_Protect.py').read_text(encoding='utf-8'))
owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ProtectMixin')
method = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'init_whitelist')
check = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'is_in_whitelist')
scope = {'os': os, 'component_digest': component_digest, 'is_menu_component_copy': is_menu_component_copy}
exec(compile(ast.Module(body=[method, check], type_ignores=[]), 'PYAS_Protect.py', 'exec'), scope)
API = type('API', (), {name: scope[name] for name in ('init_whitelist', 'is_in_whitelist')})


class BuiltinWhitelistTests(unittest.TestCase):
    def test_installed_menu_component_is_exact_file_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            api = API()
            api.path_pyas = directory
            api.file_pyas = str(Path(directory) / 'PYAS.exe')
            menu = Path(directory) / 'PYAS_Menu.exe'
            menu.write_bytes(b'fixture')
            api.manage_named_list = Mock()
            api.init_whitelist()
            self.assertEqual(api._menu_component_digest, component_digest(menu))
            api.manage_named_list.assert_called_once_with('white_list', [api.file_pyas, str(menu)], action='add')

    def test_missing_helper_or_directory_is_not_added(self):
        with tempfile.TemporaryDirectory() as directory:
            api = API()
            api.path_pyas = directory
            api.file_pyas = str(Path(directory) / 'PYAS.exe')
            api.manage_named_list = Mock()
            api.init_whitelist()
            api.manage_named_list.assert_called_once_with('white_list', [api.file_pyas], action='add')
            (Path(directory) / 'PYAS_Menu.exe').mkdir()
            api.manage_named_list.reset_mock()
            api.init_whitelist()
            api.manage_named_list.assert_called_once_with('white_list', [api.file_pyas], action='add')

    def test_menu_registration_follows_synchronous_whitelist_initialization(self):
        text = (root / 'PYAS_Scanner.py').read_text(encoding='utf-8')
        self.assertLess(text.index('self.init_whitelist()'), text.index('self.register_context_menu(context_enabled)'))
        self.assertNotIn('self.start_daemon_thread(self.init_whitelist)', text)

    def test_copy_requires_installed_content_and_correct_name(self):
        with tempfile.TemporaryDirectory() as directory:
            installed = Path(directory) / 'installed' / 'PYAS_Menu.exe'
            installed.parent.mkdir()
            installed.write_bytes(b'trusted component')
            expected = component_digest(installed)
            copy = Path(directory) / 'PYAS_Menu.exe'
            copy.write_bytes(installed.read_bytes())
            self.assertTrue(is_menu_component_copy(copy, expected))
            self.assertFalse(is_menu_component_copy(copy, None))
            copy.write_bytes(b'replaced component')
            self.assertFalse(is_menu_component_copy(copy, expected))
            renamed = Path(directory) / 'other.exe'
            renamed.write_bytes(installed.read_bytes())
            self.assertFalse(is_menu_component_copy(renamed, expected))

    def test_digest_rejects_missing_empty_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'PYAS_Menu.exe'
            self.assertIsNone(component_digest(target))
            target.touch()
            self.assertIsNone(component_digest(target))
            with target.open('wb') as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            self.assertIsNone(component_digest(target))

    def test_scan_whitelist_uses_content_trust_without_persisting_copy_path(self):
        with tempfile.TemporaryDirectory() as directory:
            api = API()
            api.path_pyas = str(Path(directory) / 'installed')
            Path(api.path_pyas).mkdir()
            api.file_pyas = str(Path(api.path_pyas) / 'PYAS.exe')
            (Path(api.path_pyas) / 'PYAS_Menu.exe').write_bytes(b'component')
            api.manage_named_list = Mock()
            api.lock_config = threading.RLock()
            api.pyas_config = {'white_list': []}
            api.norm_path = lambda path, must_exist=False: os.path.abspath(path) if path else None
            api.init_whitelist()
            candidate = Path(directory) / 'PYAS_Menu.exe'
            candidate.write_bytes(b'component')
            self.assertTrue(api.is_in_whitelist(str(candidate)))
            candidate.write_bytes(b'different')
            self.assertFalse(api.is_in_whitelist(str(candidate)))
            self.assertEqual(api.pyas_config['white_list'], [])


if __name__ == '__main__':
    unittest.main()
