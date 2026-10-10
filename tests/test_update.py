"""Execute the production update methods without starting Windows services."""
import ast
import re
import unittest
from pathlib import Path
from unittest.mock import Mock
import requests
from PYAS_Version import VERSION

tree = ast.parse((Path(__file__).resolve().parents[1] / 'PYAS_Tools.py').read_text(encoding='utf-8'))
main = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ToolsMixin')
names = {'check_update', 'compare_versions'}
scope = {'requests': requests, 're': re, 'VERSION': VERSION, 'log_exception': Mock()}
exec(compile(ast.Module(body=[n for n in main.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[]), 'PYAS_Tools.py', 'exec'), scope)
UpdateAPI = type('UpdateAPI', (), {name: scope[name] for name in names})

class UpdateTests(unittest.TestCase):
    def api(self, status, payload):
        api = UpdateAPI()
        response = Mock(status_code=status)
        response.json.return_value = payload
        api._github_get = Mock(return_value=response)
        return api

    def test_repository_error_not_reported_as_latest(self):
        for status, code in [(404, 'repository_unavailable'), (403, 'rate_limited'), (429, 'rate_limited')]:
            self.assertEqual(self.api(status, {}).check_update()['error_code'], code)

    def test_empty_and_malformed_responses(self):
        self.assertTrue(self.api(200, []).check_update()['no_release'])
        self.assertEqual(self.api(200, {'message': 'failure'}).check_update()['error_code'], 'invalid_response')

    def test_version_and_installer_selection(self):
        url = 'https://github.com/upcyan/PYAS_cyanmod/releases/download/v9.0.0-2/PYAS_Setup_v9.0.0-2.exe'
        releases = [
            {'tag_name': 'v9.0.0-1', 'assets': []},
            {'tag_name': 'v99.0.0-1', 'prerelease': True},
            {'tag_name': 'v9.0.0-2', 'assets': [
                {'name': 'PYAS_Menu.exe', 'browser_download_url': url},
                {'name': 'PYAS_Setup_v9.0.0-2.exe', 'browser_download_url': 'https://example.test/evil.exe'},
                {'name': 'PYAS_Setup_v9.0.0-2.exe', 'browser_download_url': url, 'size': 42},
            ]},
        ]
        result = self.api(200, releases).check_update()
        self.assertTrue(result['has_update'])
        self.assertEqual(result['latest'], 'v9.0.0-2')
        self.assertEqual(result['asset']['url'], url)
        api = UpdateAPI()
        self.assertTrue(api.compare_versions('3.7.0', 'v3.7.0-0'))
        self.assertTrue(api.compare_versions('3.7.0-2', 'v3.7.0-1'))

    def test_network_error_has_actionable_code(self):
        api = UpdateAPI()
        api._github_get = Mock(side_effect=requests.ConnectTimeout())
        self.assertEqual(api.check_update()['error_code'], 'network_error')
