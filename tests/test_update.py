"""Execute the production update methods without starting Windows services."""
import ast
import os
import re
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import requests
import PYAS_Channel
from PYAS_Version import VERSION, UPSTREAM_REPO, UPSTREAM_TRACKED


class _FakeWinreg:
    """只实现 _system_proxy_candidates 用到的注册表入口,值由用例切换。"""
    HKEY_CURRENT_USER = 0
    HKEY_LOCAL_MACHINE = 1
    KEY_READ = 0
    VALUES = {}
    WINHTTP_SERVER = ""

    class _Key:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    @classmethod
    def OpenKey(cls, *args, **kwargs):
        return cls._Key()

    @classmethod
    def QueryValueEx(cls, key, name):
        if name == 'WinHttpSettings':
            # WinHTTP 的二进制:4 字节标志 + 若干「长度 + UTF-16 串」
            server = cls.WINHTTP_SERVER.encode('utf-16-le')
            blob = (0).to_bytes(4, 'little') + len(server).to_bytes(4, 'little') + server
            return blob, 1
        if name not in cls.VALUES:
            raise FileNotFoundError(name)
        return cls.VALUES[name], 1


tree = ast.parse((Path(__file__).resolve().parents[1] / 'PYAS_Tools.py').read_text(encoding='utf-8'))
main = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ToolsMixin')
names = {'check_update', '_check_self_update', '_is_dev_channel', '_check_upstream_update', 'compare_versions',
    '_system_proxy_candidates'}
scope = {'requests': requests, 're': re, 'os': os, 'winreg': _FakeWinreg, 'VERSION': VERSION,
    'UPSTREAM_REPO': UPSTREAM_REPO, 'UPSTREAM_TRACKED': UPSTREAM_TRACKED, 'log_exception': Mock()}
exec(compile(ast.Module(body=[n for n in main.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[]), 'PYAS_Tools.py', 'exec'), scope)
UpdateAPI = type('UpdateAPI', (), {name: scope[name] for name in names})

class UpdateTests(unittest.TestCase):
    def setUp(self):
        # 本文件只测自身仓库的检查逻辑:强制普通模式,免得构建机上的
        # PYAS_Build.py(开发者模式)让用例多出一次上游请求
        self._saved = PYAS_Channel.IS_DEV
        PYAS_Channel.IS_DEV = False

    def tearDown(self):
        PYAS_Channel.IS_DEV = self._saved

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

    def test_registry_proxy_respects_enable_flag(self):
        # 回归:ProxyEnable=0 时 ProxyServer 只是残留配置,拿去当代理会打到已停用端口
        api = UpdateAPI()
        with patch.dict(os.environ, {}, clear=True):
            _FakeWinreg.VALUES = {'ProxyEnable': 0, 'ProxyServer': '127.0.0.1:26561'}
            self.assertEqual(api._system_proxy_candidates(), [])

            _FakeWinreg.VALUES = {'ProxyEnable': 1, 'ProxyServer': '127.0.0.1:7890'}
            self.assertEqual(api._system_proxy_candidates(), ['http://127.0.0.1:7890'])

    def test_registry_proxy_per_protocol_form(self):
        api = UpdateAPI()
        with patch.dict(os.environ, {}, clear=True):
            _FakeWinreg.VALUES = {'ProxyEnable': 1, 'ProxyServer': 'http=127.0.0.1:7890;https=127.0.0.1:7891'}
            self.assertEqual(api._system_proxy_candidates(),
                ['http://127.0.0.1:7891', 'http://127.0.0.1:7890'])

    def test_winhttp_proxy_is_used_when_ie_settings_are_empty(self):
        # WinHTTP(netsh winhttp set proxy)与 IE 设置是两套;只配了前者时也要能取到
        api = UpdateAPI()
        with patch.dict(os.environ, {}, clear=True):
            _FakeWinreg.VALUES = {}
            _FakeWinreg.WINHTTP_SERVER = ""
            self.assertEqual(api._system_proxy_candidates(), [])

            _FakeWinreg.WINHTTP_SERVER = "127.0.0.1:8080"
            self.assertEqual(api._system_proxy_candidates(), ["http://127.0.0.1:8080"])
            _FakeWinreg.WINHTTP_SERVER = ""

    def test_registry_proxy_missing_values(self):
        api = UpdateAPI()
        with patch.dict(os.environ, {}, clear=True):
            _FakeWinreg.VALUES = {}
            self.assertEqual(api._system_proxy_candidates(), [])
