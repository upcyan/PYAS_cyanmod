"""构建渠道的写入与运行时解析。

需求（2026-10-12）：本地构建 = 开发者模式，GitHub 构建 = 普通模式。
渠道在打包前写进生成模块 PYAS_Build.py，运行时由 PYAS_Channel.py 读取。
本文件锁定：
  1. local → dev、release → normal 的默认映射（含菜单与 CLI 两条入口）；
  2. 生成文件的内容格式，以及 PYAS_Channel 能正确解析；
  3. **生成文件缺失时按普通模式**——漏了构建步骤也不能把开发能力带进发布包；
  4. CI 工作流显式声明普通模式（发布包必须不含上游跟进特性）。
"""
import importlib
import sys
import unittest
from pathlib import Path

import build
import PYAS_Channel

CHANNEL_FILE = Path(build.CHANNEL_FILE)
WORKFLOW = Path(build.ROOT) / '.github' / 'workflows' / 'release.yml'


class BuildChannelTests(unittest.TestCase):
    def setUp(self):
        self._backup = CHANNEL_FILE.read_text(encoding='utf-8') if CHANNEL_FILE.exists() else None

    def tearDown(self):
        if self._backup is None:
            CHANNEL_FILE.unlink(missing_ok=True)
        else:
            CHANNEL_FILE.write_text(self._backup, encoding='utf-8')
        self._reload()

    def _reload(self):
        # 生成文件每次都被重写,必须连模块缓存一起丢掉,否则 from PYAS_Build import
        # 会拿到上一次导入的旧模块(生产环境只在启动时导入一次,不受影响)
        sys.modules.pop('PYAS_Build', None)
        return importlib.reload(PYAS_Channel)

    def test_mode_defaults_match_requirement(self):
        self.assertEqual(build.MODE_CHANNEL, {'local': 'dev', 'release': 'normal'},
                         '本地构建必须是开发者模式,发布构建必须是普通模式')

    def test_dev_channel_written_and_resolved(self):
        build.write_build_channel('dev')
        text = CHANNEL_FILE.read_text(encoding='utf-8')
        self.assertIn('CHANNEL = "dev"', text)
        self.assertIn('build.py 生成', text, '生成文件应标明来源,避免被误提交')
        channel = self._reload()
        self.assertTrue(channel.IS_DEV)
        self.assertEqual(channel.LABEL, '开发者模式')

    def test_normal_channel_written_and_resolved(self):
        build.write_build_channel('normal')
        text = CHANNEL_FILE.read_text(encoding='utf-8')
        self.assertIn('CHANNEL = "normal"', text)
        channel = self._reload()
        self.assertFalse(channel.IS_DEV)
        self.assertEqual(channel.LABEL, '普通模式')

    def test_missing_generated_file_falls_back_to_normal(self):
        CHANNEL_FILE.unlink(missing_ok=True)
        channel = self._reload()
        self.assertFalse(channel.IS_DEV, '生成文件缺失时必须按普通模式运行')
        self.assertEqual(channel.CHANNEL, 'normal')

    def test_corrupted_generated_file_falls_back_to_normal(self):
        CHANNEL_FILE.write_text('CHANNEL = "beta"\n', encoding='utf-8')
        self.assertFalse(self._reload().IS_DEV)

    def test_unknown_channel_rejected(self):
        with self.assertRaises(SystemExit):
            build.write_build_channel('beta')

    def test_generated_file_is_ignored_by_git(self):
        ignore = (Path(build.ROOT) / '.gitignore').read_text(encoding='utf-8')
        self.assertIn('PYAS_Build.py', ignore, '生成文件不能进版本库')

    def test_read_build_channel_defaults_to_normal(self):
        CHANNEL_FILE.unlink(missing_ok=True)
        self.assertEqual(build.read_build_channel(), 'normal')
        CHANNEL_FILE.write_text('CHANNEL = "beta"\n', encoding='utf-8')
        self.assertEqual(build.read_build_channel(), 'normal', '非法值也按普通模式')

    def test_publish_guard_blocks_dev_build(self):
        build.write_build_channel('dev')
        with self.assertRaises(SystemExit):
            build.assert_publish_channel(interactive=False)

    def test_publish_guard_allows_normal_build(self):
        build.write_build_channel('normal')
        build.assert_publish_channel(interactive=False)  # 不应抛退出

    def test_ci_builds_normal_channel(self):
        workflow = WORKFLOW.read_text(encoding='utf-8')
        self.assertIn('build.py local --channel normal', workflow,
                      'CI 发布包必须显式走普通模式,否则会把开发者模式发出去')


if __name__ == '__main__':
    unittest.main()
