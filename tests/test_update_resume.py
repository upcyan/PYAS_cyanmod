"""断点续传、渠道粘滞与旁路校验软化的契约;纯内存桩,无真实网络。"""
import ast
import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock

import PYAS_Updates
from PYAS_Updates import PART_MAX_AGE, RESUME_ROUNDS, UpdateDownloadManager, normalize_asset

ROOT = Path(__file__).resolve().parents[1]


class DeferredThread:
    def __init__(self, **kwargs): self.kwargs = kwargs
    def start(self): pass


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, chunks=()):
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = tuple(chunks)
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for block in self._chunks:
            yield block

    def close(self):
        self.closed = True


def streaming_response(payload, cut_after=None, headers=None):
    """构造中流断开的响应:正常吐字节,在 cut_after 处抛连接异常。"""
    chunks = []
    remaining = payload
    if cut_after is not None:
        chunks.append(payload[:cut_after])
        remaining = payload[cut_after:]
    else:
        pass
    response = _FakeResponse(200, headers or {'Content-Length': str(len(payload))})
    def iter_content(chunk_size=65536):
        for block in chunks:
            yield block
        if cut_after is not None:
            raise ConnectionError('mid-stream reset')
        yield remaining
    response.iter_content = iter_content
    return response


class UpdateResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.payload = b'PYAS fixture payload 0123456789'
        self.fetch, self.emit, self.log = Mock(), Mock(), Mock()
        self.launcher = Mock(return_value=True)
        self.manager = UpdateDownloadManager(self.temp.name, self.fetch, self.emit, self.log,
            launcher=self.launcher, thread_factory=DeferredThread)
        self.asset = self.selected()
        self.manager.select(self.asset)

    def tearDown(self):
        PYAS_Updates.register_session_mirrors([])

    def selected(self, **changes):
        name = 'PYAS_Setup_v9.exe'
        asset = dict(name=name,
            url='https://github.com/upcyan/PYAS_cyanmod/releases/download/v9/' + name,
            size=len(self.payload), digest='sha256:' + hashlib.sha256(self.payload).hexdigest(),
            checksum_url='', version='v9')
        return normalize_asset({**asset, **changes})

    def run_download(self):
        self.assertTrue(self.manager.start(self.asset['url'], self.asset['name'], 'a' * 32)['started'])
        self.manager._download(self.manager.job)
        return self.manager.snapshot()

    def job_part(self, identifier='a'):
        """本任务 .part 的真实路径(在 manager 的 Downloads 目录,download_id 内嵌)。"""
        return Path(self.manager.directory) / (self.asset['name'] + '.' + identifier * 32 + '.part')

    def assert_no_parts(self):
        """实时防护可能短暂持有刚写出的临时文件,给清理一点时间窗。"""
        for _ in range(20):
            if not list(Path(self.temp.name).rglob('*.part')):
                return
            time.sleep(0.1)
        self.assertEqual(list(Path(self.temp.name).rglob('*.part')), [])

    def test_mid_stream_failure_resumes_from_breakpoint(self):
        first = streaming_response(self.payload, cut_after=10)
        second = _FakeResponse(206, {'Content-Range': 'bytes 10-%d/%d' % (len(self.payload) - 1, len(self.payload))},
            chunks=(self.payload[10:],))
        self.fetch.side_effect = [first, second]
        state = self.run_download()
        self.assertEqual(state['phase'], 'ready')
        self.assertEqual(state['received'], len(self.payload))
        target = Path(state['result']['path'])
        self.assertEqual(target.read_bytes(), self.payload)
        self.assertEqual(self.fetch.call_count, 2)
        self.assertEqual(self.fetch.call_args_list[1].kwargs.get('extra_headers'),
            {'Range': 'bytes=10-'})
        self.assert_no_parts()

    def test_server_ignoring_range_restarts_from_zero(self):
        first = streaming_response(self.payload, cut_after=10)
        # 服务器无视 Range 返回全量 200:必须丢弃已有字节从零重写,不许拼接
        second = _FakeResponse(200, {'Content-Length': str(len(self.payload))}, chunks=(self.payload,))
        self.fetch.side_effect = [first, second]
        state = self.run_download()
        self.assertEqual(state['phase'], 'ready')
        target = Path(state['result']['path'])
        self.assertEqual(target.read_bytes(), self.payload)
        self.assertEqual(self.fetch.call_count, 2)

    def test_resume_part_size_mismatch_falls_back_to_full_rewrite(self):
        first = streaming_response(self.payload, cut_after=10)
        # .part 在轮次之间被外部清掉:206 断点仍在 10,但盘上字节没了,
        # 防护必须放弃续传整包重写(响应体按全量内容给出才能收完整)
        second = _FakeResponse(206, {'Content-Range': 'bytes 10-%d/%d' % (len(self.payload) - 1, len(self.payload))},
            chunks=(self.payload,))
        def fetch_side_effect(*args, **kwargs):
            if self.fetch.call_count == 1:
                return first
            self.job_part().unlink(missing_ok=True)
            return second
        self.fetch.side_effect = fetch_side_effect
        state = self.run_download()
        self.assertEqual(state['phase'], 'ready')
        self.assertEqual(Path(state['result']['path']).read_bytes(), self.payload)

    def test_round_exhaustion_fails_and_cleans_part(self):
        first = streaming_response(self.payload, cut_after=10)
        self.fetch.side_effect = lambda *args, **kwargs: first
        state = self.run_download()
        self.assertEqual(state['phase'], 'failed')
        self.assertEqual(self.fetch.call_count, RESUME_ROUNDS)
        self.assert_no_parts()

    def test_oversized_part_is_rejected(self):
        bloated = _FakeResponse(200, {'Content-Length': str(len(self.payload))},
            chunks=(self.payload + b'EXTRA',))
        self.fetch.side_effect = lambda *args, **kwargs: bloated
        state = self.run_download()
        self.assertEqual(state['phase'], 'failed')
        self.launcher.assert_not_called()

    def test_stale_orphan_parts_are_pruned_fresh_ones_kept(self):
        os.makedirs(self.manager.directory, exist_ok=True)
        stale = Path(self.manager.directory) / (self.asset['name'] + '.' + 'b' * 32 + '.part')
        fresh = Path(self.manager.directory) / (self.asset['name'] + '.' + 'c' * 32 + '.part')
        stale.write_bytes(b'orphan'); fresh.write_bytes(b'other job')
        old = time.time() - PART_MAX_AGE - 3600
        os.utime(stale, (old, old))
        response = _FakeResponse(200, {'Content-Length': str(len(self.payload))}, chunks=(self.payload,))
        self.fetch.side_effect = lambda *args, **kwargs: response
        state = self.run_download()
        self.assertEqual(state['phase'], 'ready')
        for _ in range(10):
            if not stale.exists():
                break
            time.sleep(0.1)
        self.assertFalse(stale.exists())
        self.assertTrue(fresh.exists())

    def test_checksum_sidecar_failure_falls_back_to_digest(self):
        self.asset = self.selected(checksum_url=self.asset['url'] + '.sha256')
        self.manager.select(self.asset)
        download = _FakeResponse(200, {'Content-Length': str(len(self.payload))}, chunks=(self.payload,))
        def fetch_side_effect(url, **kwargs):
            if kwargs.get('timeout') == 15:
                raise ConnectionError('sidecar unreachable')
            return download
        self.fetch.side_effect = fetch_side_effect
        state = self.run_download()
        self.assertEqual(state['phase'], 'ready')
        self.assertTrue(any('sidecar' in str(call.kwargs.get('detail') or call.args)
            for call in self.log.call_args_list))

    def test_zero_available_checksum_rejects_installer(self):
        asset = dict(self.selected(checksum_url=self.asset['url'] + '.sha256'))
        asset['digest'] = None
        self.asset = self.manager.select(asset)
        download = _FakeResponse(200, {'Content-Length': str(len(self.payload))}, chunks=(self.payload,))
        def fetch_side_effect(url, **kwargs):
            if kwargs.get('timeout') == 15:
                raise ConnectionError('sidecar unreachable')
            return download
        self.fetch.side_effect = fetch_side_effect
        state = self.run_download()
        self.assertEqual(state['phase'], 'failed')
        self.launcher.assert_not_called()

    def test_open_stream_channel_contract(self):
        manager = self.manager
        manager.fetch = self.fetch = Mock()
        ok = _FakeResponse(200, {}, chunks=(b'',))
        self.fetch.return_value = ok
        response, resumed = manager._open_stream('https://github.com/x', offset=0)
        self.assertIs(response, ok); self.assertFalse(resumed)
        self.assertNotIn('extra_headers', self.fetch.call_args.kwargs)

        resume = _FakeResponse(206, {'Content-Range': 'bytes 10-99/100'})
        self.fetch.return_value = resume
        response, resumed = manager._open_stream('https://github.com/x', offset=10)
        self.assertTrue(resumed)
        self.assertEqual(self.fetch.call_args.kwargs.get('extra_headers'), {'Range': 'bytes=10-'})

        wrong = _FakeResponse(206, {'Content-Range': 'bytes 5-99/100'})
        self.fetch.return_value = wrong
        with self.assertRaises(ValueError):
            manager._open_stream('https://github.com/x', offset=10)
        self.assertTrue(wrong.closed)

        ignore = _FakeResponse(200, {})
        self.fetch.return_value = ignore
        response, resumed = manager._open_stream('https://github.com/x', offset=10)
        self.assertFalse(resumed)

        lost = _FakeResponse(404, {})
        self.fetch.return_value = lost
        with self.assertRaises(ValueError):
            manager._open_stream('https://github.com/x', offset=10)
        self.assertTrue(lost.closed)


class _FakeRequests:
    class RequestException(Exception):
        pass

    class Response:
        def __init__(self, status_code):
            self.status_code = status_code
            self.closed = False
        def close(self):
            self.closed = True

    def __init__(self, behavior):
        self.behavior = behavior
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        outcome = self.behavior(url)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class GithubGetChannelTests(unittest.TestCase):
    """_github_get 的渠道粘滞与非 API 主机不短路契约(AST 提取,假 requests)。"""

    @classmethod
    def setUpClass(cls):
        import re as _re
        tree = ast.parse((ROOT / 'PYAS_Tools.py').read_text(encoding='utf-8'))
        main = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ToolsMixin')
        fn = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == '_github_get')
        scope = {'requests': None, 'log_exception': Mock()}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), 'PYAS_Tools.py', 'exec'), scope)
        # staticmethod 保持原函数,避免被类属性描述符绑成测试类的方法
        cls.github_get = staticmethod(scope['_github_get'])

    def setUp(self):
        PYAS_Updates.register_session_mirrors([])
        self.direct = 'https://github.com/upcyan/PYAS_cyanmod/releases/download/v9/PYAS_Setup_v9.exe'
        self.mirrors = PYAS_Updates.effective_mirrors()

    def api(self, behavior):
        fake = _FakeRequests(behavior)
        # AST 提取的函数体其 globals 是 exec 的 scope 字典,按用例替换 requests
        self.github_get.__globals__['requests'] = fake
        app = type('API', (), {
            '_github_get': self.github_get,
            'GITHUB_RELEASE_HEADERS': {'User-Agent': 'PYAS-Cyanmod'},
            '_system_proxy_candidates': lambda self: [],
        })()
        return app, fake

    def test_successful_channel_becomes_sticky_for_next_call(self):
        responses = {'direct': _FakeRequests.Response(500)}
        for index, mirror in enumerate(self.mirrors):
            responses[mirror] = _FakeRequests.Response(500) if index == 0 else _FakeRequests.Response(200)
        def behavior(url):
            if url == self.direct:
                return responses['direct']
            for mirror in self.mirrors:
                if url.startswith(mirror):
                    return responses[mirror]
            raise AssertionError('unexpected url ' + url)
        app, fake = self.api(behavior)
        response = self.github_get(app, self.direct)
        self.assertEqual(response.status_code, 200)
        # 直连、镜像1 失败,镜像2 成功:粘滞记忆指向镜像2(index 2 = 1 直连 + 1 失败镜像)
        winner = app._github_channel_hint
        self.assertEqual(self.mirrors[1] + self.direct, fake.calls[winner[0]][0])
        self.github_get(app, self.direct)
        self.assertEqual(fake.calls[-1][0], self.mirrors[1] + self.direct)

    def test_api_rate_limit_short_circuits_but_mirror_403_does_not(self):
        # api.github.com 的 403 是真实限流,拿到就返回,不再试镜像
        app, fake = self.api(lambda url: _FakeRequests.Response(403))
        response = self.github_get(app, 'https://api.github.com/repos/x/releases')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(fake.calls), 1)
        # 非 API 主机(下载/旁路文件)的 403 按渠道不可用处理,阶梯走满
        app2, fake2 = self.api(lambda url: _FakeRequests.Response(403))
        response = self.github_get(app2, self.direct)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(fake2.calls), 1 + len(self.mirrors))

    def test_extra_headers_merge_with_release_headers(self):
        app, fake = self.api(lambda url: _FakeRequests.Response(200))
        self.github_get(app, self.direct, extra_headers={'Range': 'bytes=5-'})
        headers = fake.calls[0][1]['headers']
        self.assertEqual(headers['Range'], 'bytes=5-')
        self.assertEqual(headers['User-Agent'], 'PYAS-Cyanmod')

    def test_all_channels_down_raises_last_network_error(self):
        failure = _FakeRequests.RequestException('all down')
        app, fake = self.api(lambda url: failure)
        with self.assertRaises(_FakeRequests.RequestException):
            self.github_get(app, self.direct)
        self.assertEqual(len(fake.calls), 1 + len(self.mirrors))


class SessionMirrorTests(unittest.TestCase):
    def setUp(self):
        PYAS_Updates.register_session_mirrors([])

    def tearDown(self):
        PYAS_Updates.register_session_mirrors([])

    def test_register_validates_and_caps_entries(self):
        accepted = PYAS_Updates.register_session_mirrors([
            'https://mirror-a.example.com',            # 无尾斜杠,自动补
            'https://mirror-b.example.com/',           # 合规
            'http://insecure.example.com/',            # 非 https,拒
            'https://user:pass@c.example.com/',        # 带凭据,拒
            'https://d.example.com/path?q=1/',         # 带 query,拒
            'not a url',                               # 拒
            12345,                                     # 拒
        ])
        self.assertEqual(accepted, ['https://mirror-a.example.com/', 'https://mirror-b.example.com/'])
        self.assertIn('https://mirror-a.example.com/', PYAS_Updates.effective_mirrors())
        # 基础镜像去重
        self.assertNotIn(PYAS_Updates.RELEASE_MIRRORS[0], PYAS_Updates.effective_mirrors()[len(PYAS_Updates.RELEASE_MIRRORS):])

    def test_capacity_and_reset(self):
        accepted = PYAS_Updates.register_session_mirrors(
            ['https://m%d.example.com/' % i for i in range(10)])
        self.assertEqual(len(accepted), 6)
        self.assertEqual(len(PYAS_Updates.effective_mirrors()), len(PYAS_Updates.RELEASE_MIRRORS) + 6)
        PYAS_Updates.register_session_mirrors([])
        self.assertEqual(PYAS_Updates.effective_mirrors(), PYAS_Updates.RELEASE_MIRRORS)


if __name__ == '__main__':
    unittest.main()
