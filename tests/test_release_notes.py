"""Release 说明的来源与格式。

需求（2026-10-15）：push tag 后由 CI 自动创建 Release，说每次发版的说明正文都要人工写明，
不能沿用上一次的内容。教训：v3.7.0-24 那两版把说明写成 build.py 里的字面量，
后来没人记得改，后续版本一直在复用那段旧文案。

本文件锁定：
  1. 正文取自仓库根目录的 RELEASE_NOTES.md，不是代码里的字面量；
  2. 抬头「PYAS Security Cyanmod v<版本>」由 read_release_notes 按版本号生成，
     文件里若误留了抬头会被剥掉重写（避免复制上一版时版本串味）；
  3. 文件缺失或为空直接阻断发布，而不是带着一串空说明继续；
  4. 当前 PYAS_Version.py 的版本号确实有对应的说明文件——防止只升了版本号就发版。
"""
import tempfile
import unittest
from pathlib import Path

import build


class ReadReleaseNotesTests(unittest.TestCase):
    def test_title_is_generated_from_version(self):
        notes = build.read_release_notes('1.2.3')
        self.assertTrue(notes.startswith('PYAS Security Cyanmod v1.2.3\n\n'))
        self.assertNotIn('v9.9.9', notes.split('\n')[0])

    def test_both_publish_paths_use_the_notes_file(self):
        """gh 与 API 两条发布路径都得读 RELEASE_NOTES.md，不许任何一条写死文案。"""
        source = Path(build.__file__).read_text(encoding='utf-8')
        for fn in ('create_release_gh', 'create_release_api'):
            segment = source.split('def %s(' % fn, 1)[1].split('\ndef ', 1)[0]
            self.assertIn('read_release_notes(version)', segment, fn)

    def test_body_comes_from_file_not_literal(self):
        body = build.RELEASE_NOTES_FILE.read_text(encoding='utf-8').strip()
        notes = build.read_release_notes('9.9.9')
        self.assertTrue(notes.endswith(body.split('\n')[-1]))
        # build.py 里不再残留上一次发布用的字面量文案
        source = Path(build.__file__).read_text(encoding='utf-8')
        self.assertNotIn('Win11 右键菜单扫描兼容', source)


class MissingNotesTests(unittest.TestCase):
    def setUp(self):
        self.real = build.RELEASE_NOTES_FILE

    def tearDown(self):
        build.RELEASE_NOTES_FILE = self.real

    def test_missing_file_blocks_release(self):
        build.RELEASE_NOTES_FILE = Path(build.ROOT) / 'RELEASE_NOTES_missing.md'
        with self.assertRaises(SystemExit):
            build.read_release_notes('1.0.0')

    def test_empty_file_blocks_release(self):
        self._write('   \n\n')
        with self.assertRaises(SystemExit):
            build.read_release_notes('1.0.0')

    def test_duplicated_title_is_replaced(self):
        self._write('PYAS Security Cyanmod v0.0.0\n\n- 旧条目')
        notes = build.read_release_notes('2.0.0')
        self.assertTrue(notes.startswith('PYAS Security Cyanmod v2.0.0\n\n'))
        self.assertNotIn('v0.0.0', notes)
        self.assertIn('旧条目', notes)

    def _write(self, text):
        with tempfile.NamedTemporaryFile('w', suffix='.md', encoding='utf-8', delete=False) as fh:
            fh.write(text)
            self.addCleanup(lambda: Path(fh.name).unlink(missing_ok=True))
            build.RELEASE_NOTES_FILE = Path(fh.name)


class CurrentVersionHasNotes(unittest.TestCase):
    def test_notes_file_exists_for_current_version(self):
        version = build.read_version()
        self.assertTrue(
            build.RELEASE_NOTES_FILE.is_file(),
            f'当前版本 {version} 缺 {build.RELEASE_NOTES_FILE.name}',
        )
        self.assertGreater(len(build.RELEASE_NOTES_FILE.read_text(encoding='utf-8').strip()), 0)


if __name__ == '__main__':
    unittest.main()
