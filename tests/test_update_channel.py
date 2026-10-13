"""构建渠道与上游跟进检查。

需求（2026-10-12）：
  本地构建 = 开发者模式，装好后「检查更新」会**顺带比对上游 87owo/PYAS**，
  发现上游有新版本就提示跟进；GitHub 构建 = 普通模式，不含这套能力。

渠道由 build.py 在打包前写入生成模块 PYAS_Build.py，运行时经 PYAS_Channel 读取。
本文件锁定两件事：
  1. 开发者模式下 check_update 结果里会多出 upstream 字段，且比对口径正确；
  2. 普通模式下**完全没有**这个字段——发布包不会露出上游提示；
     上游侧任何失败（404/限流/网络异常）都只降级成 upstream.error，
     绝不影响本仓库自身的检查结果。
"""
import ast
import re
import unittest
from pathlib import Path
from unittest.mock import Mock

import requests
import PYAS_Channel
from PYAS_Version import VERSION, UPSTREAM_REPO, UPSTREAM_TRACKED

tree = ast.parse((Path(__file__).resolve().parents[1] / 'PYAS_Tools.py').read_text(encoding='utf-8'))
main = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ToolsMixin')
names = {'check_update', '_check_self_update', '_is_dev_channel', '_check_upstream_update', 'compare_versions'}
scope = {'requests': requests, 're': re, 'VERSION': VERSION, 'UPSTREAM_REPO': UPSTREAM_REPO,
         'UPSTREAM_TRACKED': UPSTREAM_TRACKED, 'log_exception': Mock()}
exec(compile(ast.Module(body=[n for n in main.body if isinstance(n, ast.FunctionDef) and n.name in names],
                        type_ignores=[]), 'PYAS_Tools.py', 'exec'), scope)
UpdateAPI = type('UpdateAPI', (), {name: scope[name] for name in names})

# 自身仓库给一个明确更新的版本,这样 has_update=True 与上游比对互不干扰
SELF_RELEASES = [{'tag_name': 'v9.0.0-1', 'assets': []}]


class UpdateChannelTests(unittest.TestCase):
    def setUp(self):
        self._saved = PYAS_Channel.IS_DEV

    def tearDown(self):
        PYAS_Channel.IS_DEV = self._saved

    def api(self, *, dev=True, self_status=200, self_payload=None, upstream_status=200,
            upstream_payload=None, upstream_exc=None):
        """按 URL 分派 _github_get：本仓库与上游各自返回不同的假响应。"""
        PYAS_Channel.IS_DEV = dev
        api = UpdateAPI()

        def fake_get(url, **kwargs):
            if UPSTREAM_REPO in url:
                if upstream_exc is not None:
                    raise upstream_exc
                response = Mock(status_code=upstream_status)
                response.json.return_value = upstream_payload if upstream_payload is not None else []
                return response
            response = Mock(status_code=self_status)
            response.json.return_value = SELF_RELEASES if self_payload is None else self_payload
            return response

        api._github_get = fake_get
        return api

    # ---------------- 开发者模式 ----------------

    def test_dev_channel_reports_newer_upstream(self):
        result = self.api(dev=True, upstream_payload=[
            {'tag_name': 'v3.6.9'},
            {'tag_name': 'v3.7.1', 'body': 'upstream notes', 'published_at': '2026-10-01T00:00:00Z'},
        ]).check_update()
        upstream = result.get('upstream')
        self.assertIsNotNone(upstream, '开发者模式必须带上 upstream 字段')
        self.assertTrue(upstream['supported'])
        self.assertTrue(upstream['has_update'])
        self.assertEqual(upstream['latest'], 'v3.7.1')
        self.assertEqual(upstream['tracked'], UPSTREAM_TRACKED)
        self.assertEqual(upstream['repository'], UPSTREAM_REPO)
        self.assertIn(UPSTREAM_REPO, upstream['url'])
        self.assertEqual(upstream['body'], 'upstream notes')
        self.assertEqual(upstream['published_at'], '2026-10-01')

    def test_dev_channel_silent_when_upstream_not_newer(self):
        for tags in ([{'tag_name': 'v3.7.0'}], [{'tag_name': 'v3.6.0'}], [{'tag_name': UPSTREAM_TRACKED}]):
            with self.subTest(tags=tags):
                upstream = self.api(dev=True, upstream_payload=tags).check_update()['upstream']
                self.assertFalse(upstream['has_update'], tags)
                self.assertFalse(upstream.get('error', False))

    def test_upstream_ignores_prerelease_and_draft(self):
        payload = [
            {'tag_name': 'v9.9.9', 'prerelease': True},
            {'tag_name': 'v9.9.8', 'draft': True},
            {'tag_name': 'nightly-build'},
        ]
        upstream = self.api(dev=True, upstream_payload=payload).check_update()['upstream']
        self.assertFalse(upstream['has_update'])
        self.assertEqual(upstream['latest'], UPSTREAM_TRACKED, '没有可用的上游发布时应回落到跟进版本')

    def test_upstream_http_errors_do_not_touch_self_result(self):
        for status, code in [(404, 'repository_unavailable'), (403, 'rate_limited'), (429, 'rate_limited')]:
            with self.subTest(status=status):
                result = self.api(dev=True, upstream_status=status).check_update()
                upstream = result['upstream']
                self.assertTrue(upstream['error'])
                self.assertEqual(upstream['error_code'], code)
                self.assertNotIn('error', result, '上游出错不能把自身检查结果也标成错误')

    def test_upstream_network_error_degrades_only_upstream(self):
        result = self.api(dev=True, upstream_exc=requests.ConnectTimeout()).check_update()
        self.assertEqual(result['upstream']['error_code'], 'network_error')
        self.assertTrue(result['has_update'], '自身检查结果不受影响')
        self.assertEqual(result['latest'], 'v9.0.0-1')

    def test_self_error_still_carries_upstream(self):
        result = self.api(dev=True, self_status=404, upstream_payload=[{'tag_name': 'v3.7.1'}]).check_update()
        self.assertEqual(result['error_code'], 'repository_unavailable')
        self.assertTrue(result['upstream']['has_update'])

    def test_upstream_shape_stable_when_no_release(self):
        upstream = self.api(dev=True, upstream_payload=[]).check_update()['upstream']
        self.assertEqual(upstream['tracked'], UPSTREAM_TRACKED)
        self.assertFalse(upstream['has_update'])
        self.assertIn('url', upstream)

    # ---------------- 普通模式 ----------------

    def test_normal_channel_omits_upstream_entirely(self):
        result = self.api(dev=False, upstream_payload=[{'tag_name': 'v3.7.1'}]).check_update()
        self.assertNotIn('upstream', result, '普通模式（发布包）不应包含上游相关字段')
        self.assertTrue(result['has_update'])

    def test_normal_channel_never_requests_upstream(self):
        asked = []
        api = UpdateAPI()
        PYAS_Channel.IS_DEV = False

        def fake_get(url, **kwargs):
            asked.append(url)
            response = Mock(status_code=200)
            response.json.return_value = SELF_RELEASES
            return response

        api._github_get = fake_get
        api.check_update()
        self.assertEqual(len(asked), 1, '普通模式只应请求本仓库一次')
        self.assertNotIn(UPSTREAM_REPO, asked[0])


if __name__ == '__main__':
    unittest.main()
