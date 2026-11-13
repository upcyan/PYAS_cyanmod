"""更新清单兜底(latest.json)与变更记录桥的契约;AST 提取 + 假 requests。"""
import ast
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

import requests

import PYAS_Channel
import PYAS_Updates

ROOT = Path(__file__).resolve().parents[1]

REPO = 'upcyan/PYAS_cyanmod'

tree = ast.parse((ROOT / 'PYAS_Tools.py').read_text(encoding='utf-8'))
main = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ToolsMixin')
NAMES = {'check_update', '_check_self_update', '_fetch_update_manifest', 'fetch_release_changelog',
    'compare_versions', '_is_dev_channel'}
scope = {'requests': requests, 're': __import__('re'), 'os': __import__('os'), 'json': json,
    'time': __import__('time'), 'VERSION': '3.7.2-1', 'UPSTREAM_REPO': '87owo/PYAS', 'log_exception': Mock()}
exec(compile(ast.Module(body=[n for n in main.body if isinstance(n, ast.FunctionDef) and n.name in NAMES],
    type_ignores=[]), 'PYAS_Tools.py', 'exec'), scope)


def manifest_payload(version='v99.0.0-9'):
    name = 'PYAS_Setup_v99.0.0-9.exe'
    return {
        'version': version,
        'published_at': '2026-11-14T00:00:00Z',
        'notes': 'fixture notes',
        'asset': {
            'name': name,
            'url': f'https://github.com/{REPO}/releases/download/{version}/{name}',
            'size': 1234,
            'digest': 'sha256:' + 'ab' * 32,
            'checksum_url': f'https://github.com/{REPO}/releases/download/{version}/{name}.sha256',
            'version': version,
        },
        'mirrors': [],
    }


def manifest_result(version='v99.0.0-9'):
    """_fetch_update_manifest 的返回形状(原始清单由 ManifestFetchTests 单独测)。"""
    payload = manifest_payload(version)
    return {
        'has_update': version != '3.7.2-1',
        'latest': version,
        'current': '3.7.2-1',
        'url': f'https://github.com/{REPO}/releases',
        'asset': payload['asset'],
        'body': 'fixture notes',
        'published_at': '2026-11-14',
        'via': 'manifest',
    }


class ManifestFallbackTests(unittest.TestCase):
    def setUp(self):
        self._saved_channel = PYAS_Channel.IS_DEV
        PYAS_Channel.IS_DEV = False
        PYAS_Updates.register_session_mirrors([])

    def tearDown(self):
        PYAS_Channel.IS_DEV = self._saved_channel
        PYAS_Updates.register_session_mirrors([])

    def api(self, manifest_side_effect=None):
        app = type('UpdateAPI', (), {name: scope[name] for name in NAMES})()
        app.GITHUB_RELEASE_HEADERS = {'User-Agent': 'PYAS-Cyanmod'}
        app._github_get = Mock(side_effect=requests.ConnectionError('api down'))
        app._fetch_update_manifest = (Mock(side_effect=manifest_side_effect)
            if manifest_side_effect is not None else Mock(return_value=manifest_result()))
        return app

    def test_manifest_is_used_when_api_is_unreachable(self):
        app = self.api()
        result = app.check_update()
        self.assertFalse(result.get('error'))
        self.assertEqual(result['via'], 'manifest')
        self.assertTrue(result['has_update'])
        self.assertEqual(result['latest'], 'v99.0.0-9')
        self.assertEqual(result['asset']['name'], 'PYAS_Setup_v99.0.0-9.exe')
        self.assertTrue(result['asset'].get('asset_id'))

    def test_network_error_when_manifest_unavailable(self):
        app = self.api(manifest_side_effect=OSError('manifest unreachable'))
        result = app.check_update()
        self.assertEqual(result['error_code'], 'network_error')

    def test_rate_limit_answer_does_not_consult_manifest(self):
        app = self.api()
        response = Mock(status_code=403)
        app._github_get = Mock(return_value=response)
        result = app.check_update()
        self.assertEqual(result['error_code'], 'rate_limited')
        app._fetch_update_manifest.assert_not_called()

    def test_superseded_protection_is_untouched_by_manifest(self):
        # 清单兜底只发生在 _check_self_update 内部;并发代际保护由
        # test_update_protocol 锁定,这里仅确认正常代际递增后清单结果可用
        app = self.api()
        first = app.check_update()
        self.assertEqual(first['via'], 'manifest')
        app._github_get = Mock(side_effect=requests.ConnectionError())
        second = app.check_update()
        self.assertEqual(second['via'], 'manifest')
        self.assertEqual(second['asset']['asset_id'], first['asset']['asset_id'])


class ManifestFetchTests(unittest.TestCase):
    """_fetch_update_manifest 自身的取数与镜像注册契约。"""

    def setUp(self):
        self._saved_channel = PYAS_Channel.IS_DEV
        PYAS_Channel.IS_DEV = False
        PYAS_Updates.register_session_mirrors([])

    def tearDown(self):
        PYAS_Channel.IS_DEV = self._saved_channel
        PYAS_Updates.register_session_mirrors([])
        scope['requests'] = requests  # 恢复共享 exec scope,别把假模块泄漏给后续用例

    def build(self, fake_requests):
        scope['requests'] = fake_requests
        app = type('UpdateAPI', (), {name: scope[name] for name in NAMES})()
        app.GITHUB_RELEASE_HEADERS = {'User-Agent': 'PYAS-Cyanmod'}
        return app, fake_requests

    def jsdelivr_url(self):
        return f'https://cdn.jsdelivr.net/gh/{REPO}@main/latest.json'

    def raw_url(self):
        return f'https://raw.githubusercontent.com/{REPO}/main/latest.json'

    def test_jsdelivr_serves_manifest(self):
        class Fake:
            RequestException = requests.RequestException
            Response = object
            def __init__(self):
                self.calls = []
            def get(self, url, **kwargs):
                self.calls.append(url)
                if url == self_jsdelivr:
                    return Mock(status_code=200, text=json.dumps(manifest_payload()))
                raise requests.ConnectionError(url)
        self_jsdelivr = self.jsdelivr_url()
        fake = Fake()
        app, _ = self.build(fake)
        result = app._fetch_update_manifest()
        self.assertEqual(fake.calls, [self.jsdelivr_url()])
        self.assertEqual(result['latest'], 'v99.0.0-9')
        self.assertTrue(result['has_update'])
        self.assertEqual(result['via'], 'manifest')

    def test_raw_via_mirror_fallback(self):
        class Fake:
            RequestException = requests.RequestException
            Response = object
            def __init__(self, ok_url):
                self.ok_url = ok_url
                self.calls = []
            def get(self, url, **kwargs):
                self.calls.append(url)
                if url == self.ok_url:
                    return Mock(status_code=200, text=json.dumps(manifest_payload()))
                raise requests.ConnectionError(url)
        mirror0 = PYAS_Updates.effective_mirrors()[0] + self.raw_url()
        fake = Fake(mirror0)
        app, _ = self.build(fake)
        result = app._fetch_update_manifest()
        self.assertEqual(fake.calls, [self.jsdelivr_url(), mirror0])
        self.assertEqual(result['latest'], 'v99.0.0-9')

    def test_manifest_mirrors_are_registered(self):
        payload = manifest_payload()
        payload['mirrors'] = ['https://cdn-self.example.com/', 'ftp://nope/']
        class Fake:
            RequestException = requests.RequestException
            Response = object
            def get(self, url, **kwargs):
                if url == self_jsdelivr:
                    return Mock(status_code=200, text=json.dumps(payload))
                raise requests.ConnectionError(url)
        self_jsdelivr = self.jsdelivr_url()
        app, _ = self.build(Fake())
        self.assertTrue(app._fetch_update_manifest())
        self.assertEqual(PYAS_Updates.effective_mirrors(),
            PYAS_Updates.RELEASE_MIRRORS + ('https://cdn-self.example.com/',))

    def test_invalid_manifest_shapes_are_rejected(self):
        for text in ('', 'not json', '[]', json.dumps({'asset': {}}), json.dumps({'version': ''})):
            with self.subTest(text=text[:20]):
                class Fake:
                    RequestException = requests.RequestException
                    Response = object
                    def __init__(self, text):
                        self.text = text
                    def get(self, url, **kwargs):
                        return Mock(status_code=200, text=self.text)
                app, _ = self.build(Fake(text))
                if text == 'not json':
                    with self.assertRaises(Exception):
                        app._fetch_update_manifest()
                else:
                    self.assertIsNone(app._fetch_update_manifest())

    def test_all_sources_down_returns_none(self):
        class Fake:
            RequestException = requests.RequestException
            Response = object
            def get(self, url, **kwargs):
                raise requests.ConnectionError(url)
        app, _ = self.build(Fake())
        self.assertIsNone(app._fetch_update_manifest())


class ChangelogBridgeTests(unittest.TestCase):
    def setUp(self):
        self._saved_channel = PYAS_Channel.IS_DEV
        PYAS_Channel.IS_DEV = False

    def tearDown(self):
        PYAS_Channel.IS_DEV = self._saved_channel

    def build(self):
        app = type('UpdateAPI', (), {name: scope[name] for name in NAMES})()
        app._github_get = Mock()
        return app

    def releases_payload(self):
        return [
            {'tag_name': 'v99.0.0-2', 'name': 'release two', 'published_at': '2026-11-14T01:00:00Z',
             'body': 'body two', 'prerelease': False},
            {'tag_name': 'v99.0.0-3', 'name': 'draft', 'body': 'secret', 'draft': True},
            {'tag_name': '', 'name': 'tagless'},
        ]

    def test_releases_are_filtered_and_cached(self):
        app = self.build()
        response = Mock(status_code=200)
        response.json.return_value = self.releases_payload()
        app._github_get.return_value = response
        result = app.fetch_release_changelog(REPO, 20)
        self.assertTrue(result['success'])
        self.assertEqual([entry['tag'] for entry in result['releases']], ['v99.0.0-2'])
        self.assertEqual(result['releases'][0]['date'], '2026-11-14')
        app.fetch_release_changelog(REPO, 20)
        app.fetch_release_changelog('87owo/PYAS', 20)
        self.assertEqual(app._github_get.call_count, 2)  # 本仓库走缓存,上游仓库单独拉取

    def test_invalid_repository_is_rejected(self):
        app = self.build()
        self.assertEqual(app.fetch_release_changelog('evil/repo')['error_code'], 'invalid_repository')
        app._github_get.assert_not_called()

    def test_http_errors_surface_as_error_code(self):
        app = self.build()
        app._github_get.return_value = Mock(status_code=403)
        self.assertEqual(app.fetch_release_changelog(REPO)['error_code'], 'http_403')

    def test_network_failure_degrades_gracefully(self):
        app = self.build()
        app._github_get = Mock(side_effect=requests.ConnectionError())
        self.assertEqual(app.fetch_release_changelog(REPO)['error_code'], 'network_error')


if __name__ == '__main__':
    unittest.main()
