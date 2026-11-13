"""R2 自有分发渠道的契约:SigV4 签名、对象 URL 推导、渠道优先级与清单接线。"""
import hashlib
import hmac
import importlib.util
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

import PYAS_Updates
from PYAS_Updates import (R2_PUBLIC_BASE, UpdateDownloadManager, normalize_asset,
    r2_manifest_url, r2_object_urls, register_session_r2_base)

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location('build', ROOT / 'build.py')
build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build)

R2_BASE = 'https://dl.example.com/'


class DeferredThread:
    def __init__(self, **kwargs): self.kwargs = kwargs
    def start(self): pass


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, chunks=(), text=''):
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = tuple(chunks)
        self.text = text
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for block in self._chunks:
            yield block

    def close(self):
        self.closed = True


def streaming_response(payload, cut_after=None, status=200, headers=None):
    """中流断开(或完整)的响应体;cut_after 后抛连接异常。"""
    chunks = (payload[:cut_after],) if cut_after is not None else (payload,)
    response = _FakeResponse(status, headers or {'Content-Length': str(len(payload))})
    def iter_content(chunk_size=65536):
        for block in chunks:
            yield block
        if cut_after is not None:
            raise ConnectionError('mid-stream reset')
    response.iter_content = iter_content
    return response


class R2BaseTests(unittest.TestCase):
    def setUp(self):
        register_session_r2_base('')

    def tearDown(self):
        register_session_r2_base('')

    def test_disabled_by_default_and_derivation(self):
        self.assertEqual(PYAS_Updates.active_r2_base(), R2_PUBLIC_BASE or '')
        self.assertIsNone(r2_object_urls({'version': 'v9', 'name': 'x.exe'}))
        self.assertIsNone(r2_manifest_url())
        self.assertTrue(register_session_r2_base('https://dl.example.com'))
        self.assertEqual(PYAS_Updates.active_r2_base(), 'https://dl.example.com/')
        urls = r2_object_urls({'version': 'v3.7.2-3', 'name': 'PYAS_Setup_v3.7.2-3.exe'})
        self.assertEqual(urls, {'installer': R2_BASE + 'releases/v3.7.2-3/PYAS_Setup_v3.7.2-3.exe',
                                'sidecar': R2_BASE + 'releases/v3.7.2-3/PYAS_Setup_v3.7.2-3.exe.sha256'})
        self.assertEqual(r2_manifest_url(), R2_BASE + 'latest.json')

    def test_registration_validation_and_clear(self):
        self.assertTrue(register_session_r2_base('https://a.example.com'))
        for bad in ('http://a.example.com/', 'https://a.example.com/p?q=1',
                    'https://u:p@a.example.com/', 'ftp://x/', 'https://a.example.com/deep/path'):
            self.assertIsNone(register_session_r2_base(bad), bad)
            self.assertEqual(PYAS_Updates.active_r2_base(), 'https://a.example.com/')
        self.assertEqual(register_session_r2_base(''), '')
        self.assertEqual(PYAS_Updates.active_r2_base(), R2_PUBLIC_BASE or '')

    def test_derivation_rejects_incomplete_assets(self):
        register_session_r2_base(R2_BASE)
        self.assertIsNone(r2_object_urls({}))
        self.assertIsNone(r2_object_urls({'version': '', 'name': 'x.exe'}))
        self.assertIsNone(r2_object_urls({'version': 'a/b', 'name': 'x.exe'}))


class R2ChannelPriorityTests(unittest.TestCase):
    """R2 直链作为下载/旁路校验的首选渠道;失败回落 GitHub 阶梯。"""

    def setUp(self):
        register_session_r2_base(R2_BASE)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.payload = b'PYAS r2 fixture payload 0123456789'
        self.fetch, self.emit, self.log = Mock(), Mock(), Mock()
        self.manager = UpdateDownloadManager(self.temp.name, self.fetch, self.emit, self.log,
            launcher=Mock(return_value=True), thread_factory=DeferredThread)
        name = 'PYAS_Setup_v9.exe'
        self.asset = normalize_asset(dict(name=name,
            url='https://github.com/upcyan/PYAS_cyanmod/releases/download/v9/' + name,
            size=len(self.payload), digest='sha256:' + hashlib.sha256(self.payload).hexdigest(),
            checksum_url='https://github.com/upcyan/PYAS_cyanmod/releases/download/v9/' + name + '.sha256',
            version='v9'))
        self.manager.select(self.asset)

    def tearDown(self):
        register_session_r2_base('')

    def test_r2_serves_installer_without_github(self):
        digest_hex = hashlib.sha256(self.payload).hexdigest()
        r2_response = _FakeResponse(200, {'Content-Length': str(len(self.payload))}, chunks=(self.payload,))
        sidecar = _FakeResponse(200, text=digest_hex + '\n')
        def fetch_side_effect(url, **kwargs):
            if url.startswith(R2_BASE):
                return r2_response if url.endswith('.exe') else sidecar
            return Mock(status_code=500)
        self.fetch.side_effect = fetch_side_effect
        self.assertTrue(self.manager.start(self.asset['url'], self.asset['name'], 'a' * 32)['started'])
        self.manager._download(self.manager.job)
        self.assertEqual(self.manager.snapshot()['phase'], 'ready')
        first_call = self.fetch.call_args_list[0]
        self.assertEqual(first_call.args[0], R2_BASE + 'releases/v9/PYAS_Setup_v9.exe')
        self.assertFalse(first_call.kwargs.get('mirrors', True))  # R2 直链不套镜像阶梯
        # 旁路校验也走 R2
        self.assertEqual(self.fetch.call_args_list[1].args[0],
            R2_BASE + 'releases/v9/PYAS_Setup_v9.exe.sha256')

    def test_r2_failure_falls_back_to_github_ladder(self):
        digest_hex = hashlib.sha256(self.payload).hexdigest()
        r2_dead = Mock(status_code=500)
        github = _FakeResponse(200, {'Content-Length': str(len(self.payload))}, chunks=(self.payload,))
        sidecar = Mock(status_code=200, text=digest_hex + '\n')
        def fetch_side_effect(url, **kwargs):
            if url.startswith(R2_BASE):
                return r2_dead
            if url.endswith('.sha256'):
                return sidecar
            return github
        self.fetch.side_effect = fetch_side_effect
        self.assertTrue(self.manager.start(self.asset['url'], self.asset['name'], 'a' * 32)['started'])
        self.manager._download(self.manager.job)
        state = self.manager.snapshot()
        self.assertEqual(state['phase'], 'ready')
        self.assertEqual(self.fetch.call_args_list[1].args[0], self.asset['url'])  # 回落 GitHub

    def test_r2_receives_range_header_on_resume(self):
        digest_hex = hashlib.sha256(self.payload).hexdigest()
        # 第一轮 R2 整包中流断开;第二轮 R2 带 Range 续传并收完整;旁路校验走 R2
        calls = []
        def ordered(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith('.sha256'):
                return _FakeResponse(200, text=digest_hex + '\n')
            if len([c for c in calls if not c[0].endswith('.sha256')]) == 1:
                return streaming_response(self.payload, cut_after=10)
            return _FakeResponse(206,
                {'Content-Range': 'bytes 10-%d/%d' % (len(self.payload) - 1, len(self.payload))},
                chunks=(self.payload[10:],))
        self.fetch.side_effect = ordered
        self.assertTrue(self.manager.start(self.asset['url'], self.asset['name'], 'a' * 32)['started'])
        self.manager._download(self.manager.job)
        self.assertEqual(self.manager.snapshot()['phase'], 'ready')
        installer_calls = [c for c in calls if not c[0].endswith('.sha256')]
        self.assertEqual(len(installer_calls), 2)
        self.assertTrue(installer_calls[1][0].startswith(R2_BASE))
        self.assertEqual(installer_calls[1][1].get('extra_headers'), {'Range': 'bytes=10-'})


class ManifestR2WiringTests(unittest.TestCase):
    """清单候选顺序(R2 直达优先)与 r2_base 会话激活。"""

    def setUp(self):
        import ast
        tree = ast.parse((ROOT / 'PYAS_Tools.py').read_text(encoding='utf-8'))
        main = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ToolsMixin')
        names = {'_fetch_update_manifest', 'compare_versions'}
        scope = {'requests': None, 're': re, 'os': os, 'json': json, 'time': __import__('time'),
            'VERSION': '3.7.2-1', 'UPSTREAM_REPO': '87owo/PYAS', 'log_exception': Mock()}
        funcs = [n for n in main.body if isinstance(n, ast.FunctionDef) and n.name in names]
        exec(compile(ast.Module(body=funcs, type_ignores=[]), 'PYAS_Tools.py', 'exec'), scope)
        self.scope = scope
        register_session_r2_base('')

    def tearDown(self):
        register_session_r2_base('')

    def manifest_payload(self, **extra):
        name = 'PYAS_Setup_v99.exe'
        return dict({
            'version': 'v99', 'published_at': '2026-11-14T00:00:00Z', 'notes': 'fixture',
            'asset': {'name': name,
                'url': 'https://github.com/upcyan/PYAS_cyanmod/releases/download/v99/' + name,
                'size': 10, 'digest': 'sha256:' + 'ab' * 32, 'version': 'v99'},
        }, **extra)

    def build_api(self, fake_requests):
        self.scope['requests'] = fake_requests
        app = type('API', (), {name: self.scope[name] for name in ('_fetch_update_manifest', 'compare_versions')})()
        app.GITHUB_RELEASE_HEADERS = {'User-Agent': 'PYAS-Cyanmod'}
        return app, fake_requests

    def test_r2_manifest_url_tried_first_when_baked(self):
        calls = []
        class Fake:
            RequestException = requests.RequestException
            Response = object
            def get(self, url, **kwargs):
                calls.append(url)
                raise requests.ConnectionError(url)
        with patch.object(PYAS_Updates, 'R2_PUBLIC_BASE', R2_BASE):
            register_session_r2_base('')
            app, _ = self.build_api(Fake())
            self.assertIsNone(app._fetch_update_manifest())
        self.assertEqual(calls[0], R2_BASE + 'latest.json')  # R2 直达候选第一位
        self.assertIn('cdn.jsdelivr.net', calls[1])

    def test_manifest_r2_base_activates_session_channel(self):
        payload = json.dumps(self.manifest_payload(r2_base='https://r2.example.com'))
        class Fake:
            RequestException = requests.RequestException
            Response = object
            def get(self, url, **kwargs):
                if 'jsdelivr' in url:
                    return Mock(status_code=200, text=payload)
                raise requests.ConnectionError(url)
        app, _ = self.build_api(Fake())
        result = app._fetch_update_manifest()
        self.assertEqual(PYAS_Updates.active_r2_base(), 'https://r2.example.com/')
        self.assertEqual(result['via'], 'manifest')

    def test_manifest_empty_r2_base_clears_session(self):
        register_session_r2_base(R2_BASE)
        payload = json.dumps(self.manifest_payload(r2_base=''))
        class Fake:
            RequestException = requests.RequestException
            Response = object
            def get(self, url, **kwargs):
                if 'jsdelivr' in url:
                    return Mock(status_code=200, text=payload)
                raise requests.ConnectionError(url)
        app, _ = self.build_api(Fake())
        app._fetch_update_manifest()
        self.assertEqual(PYAS_Updates.active_r2_base(), R2_PUBLIC_BASE or '')


class BuildR2PublishTests(unittest.TestCase):
    """build.py 侧:SigV4 签名格式与环境门控。"""

    @classmethod
    def setUpClass(cls):
        cls._saved_env = {key: os.environ.get(key) for key in
            ('R2_ACCOUNT_ID', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'R2_BUCKET', 'R2_PUBLIC_BASE')}

    @classmethod
    def tearDownClass(cls):
        for key, value in cls._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _patch_env(self, **overrides):
        env = {'R2_ACCOUNT_ID': 'acct123', 'R2_ACCESS_KEY_ID': 'AKIAEXAMPLE',
               'R2_SECRET_ACCESS_KEY': 'SKEXAMPLE', 'R2_BUCKET': 'pyas-releases',
               'R2_PUBLIC_BASE': 'https://dl.example.com'}
        env.update(overrides)
        return patch.dict(os.environ, {k: v for k, v in env.items()})

    def test_r2_env_gate_and_validation(self):
        with self._patch_env(R2_SECRET_ACCESS_KEY=''):
            self.assertIsNone(build.r2_env())  # 任一缺失即未接线
        with self._patch_env(R2_PUBLIC_BASE='http://dl.example.com'):
            self.assertIsNone(build.r2_env())  # 非 https 拒
        with self._patch_env(R2_PUBLIC_BASE='https://dl.example.com/deep'):
            self.assertIsNone(build.r2_env())  # 带路径拒
        with self._patch_env():
            config = build.r2_env()
            self.assertEqual(config['R2_PUBLIC_BASE'], 'https://dl.example.com/')

    def test_sigv4_signature_matches_independent_implementation(self):
        # 用测试内独立实现的 SigV4 链对照,锁死规范格式(host/日期/头排序/推导链)
        amz_date = '20260101T000000Z'
        datestamp = amz_date[:8]
        canonical = ('PUT\n/bkt/releases/v9/PYAS_Setup_v9.exe\n\n'
            'host:acct123.r2.cloudflarestorage.com\n'
            'x-amz-content-sha256:UNSIGNED-PAYLOAD\n'
            'x-amz-date:20260101T000000Z\n\n'
            'host;x-amz-content-sha256;x-amz-date\nUNSIGNED-PAYLOAD')
        scope = f'{datestamp}/auto/s3/aws4_request'
        sts = 'AWS4-HMAC-SHA256\n' + amz_date + '\n' + scope + '\n' + hashlib.sha256(canonical.encode()).hexdigest()
        key = hmac.new(('AWS4SKEXAMPLE').encode(), datestamp.encode(), hashlib.sha256).digest()
        for part in ('auto', 's3', 'aws4_request'):
            key = hmac.new(key, part.encode(), hashlib.sha256).digest()
        expected = hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()

        auth, out_date = build._r2_authorization('PUT', '/bkt/releases/v9/PYAS_Setup_v9.exe',
            {'host': 'acct123.r2.cloudflarestorage.com'}, 'UNSIGNED-PAYLOAD',
            'AKIAEXAMPLE', 'SKEXAMPLE', amz_date=amz_date)
        self.assertEqual(out_date, amz_date)
        self.assertIn(f'Credential=AKIAEXAMPLE/{scope}', auth)
        self.assertIn('SignedHeaders=host;x-amz-content-sha256;x-amz-date', auth)
        self.assertIn(f'Signature={expected}', auth)

    def test_write_update_manifest_carries_r2_base(self):
        # 清单模板签名带 r2_base(默认空=不宣传)且写入 JSON,应用端据此激活渠道
        self.assertEqual(list(__import__('inspect').signature(build.write_update_manifest).parameters),
            ['asset', 'version', 'digest_hex', 'r2_base'])
        source = __import__('inspect').getsource(build.write_update_manifest)
        self.assertIn('"r2_base": r2_base', source)

    def test_upload_release_to_r2_skips_without_credentials(self):
        with patch.dict(os.environ, {key: '' for key in
                ('R2_ACCOUNT_ID', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'R2_BUCKET', 'R2_PUBLIC_BASE')}):
            self.assertEqual(build.upload_release_to_r2(Path('x.exe'), Path('x.exe.sha256'), '9'), '')


if __name__ == '__main__':
    unittest.main()
