"""11 个语言段的 key 必须齐平:少一个 key 的后果是界面直接显示 key 名本身。

背景(2026-10-15):
首页总述从「写死的机翻句」改成「跟着五个防护灯走的三态文案」,顺手抽出共用空态文案,
一次往 11 个语言段里各加了 3 个 key。手工补 33 处极易漏 ——
`getMsg()` 取不到时回退成 key 字符串(见 main.js: `dict[lang][key] || key`),
漏掉的那门语言会把 `status_partial` 这样的内部标识直接画到界面上,而且只有切到该语言才看得见。

本测试静态比对 key 集合,不需要浏览器:
  1. 所有语言段的 key 集合必须与繁体段完全一致(缺 / 多都报)
  2. 首屏必需的那几个 key 必须在每一段里真的存在
"""
import io
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
I18N = os.path.join(ROOT, 'Interface', 'static', 'js', 'i18n.js')

# 语言段头:`        "traditional_switch": {`(8 空格缩进 + 引号名)
SECTION = re.compile(r'^ {8}"([a-z]+)_switch":\s*\{\s*$', re.M)
# 段内条目:`            "some_key": "值",`(12 空格缩进)
ENTRY = re.compile(r'^ {12}"([A-Za-z0-9_]+)":', re.M)

EXPECTED_SECTIONS = 11
BASE = 'traditional'

# 首屏/首页空态依赖的 key:缺一个就会在界面上露出内部标识
REQUIRED = ('status_protected', 'status_partial', 'status_off',
            'log_realtime', 'log_empty', 'log_filter_empty')


def read(path):
    return io.open(path, encoding='utf-8').read()


def sections_of(text):
    """返回 {段名: 该段文本};段尾取下一个段头之前(末段到 dict 结束)"""
    heads = [(m.group(1), m.start()) for m in SECTION.finditer(text)]
    out = {}
    for idx, (name, start) in enumerate(heads):
        end = heads[idx + 1][1] if idx + 1 < len(heads) else len(text)
        out[name] = text[start:end]
    return out


class I18nKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sections = sections_of(read(I18N))
        cls.keys = {name: set(ENTRY.findall(body)) for name, body in cls.sections.items()}

    def test_all_languages_present(self):
        self.assertEqual(len(self.sections), EXPECTED_SECTIONS,
                         '语言段数变了: %s' % sorted(self.sections))
        self.assertIn(BASE, self.sections)

    def test_key_sets_are_identical_across_languages(self):
        """任一段缺 key,该语言下就会把 key 名当文案画出来"""
        base = self.keys[BASE]
        self.assertTrue(base, '繁体段没解析到任何 key,解析器可能已失效')
        for name in sorted(self.keys):
            if name == BASE:
                continue
            missing = sorted(base - self.keys[name])
            extra = sorted(self.keys[name] - base)
            self.assertEqual((missing, extra), ([], []),
                             '%s 段 key 不平: 缺 %s / 多 %s' % (name, missing, extra))

    def test_home_status_keys_present_everywhere(self):
        for key in REQUIRED:
            for name in sorted(self.keys):
                self.assertIn(key, self.keys[name], '%s 段缺 %s' % (name, key))

    def test_home_status_keys_are_non_empty(self):
        """有 key 但值是空串同样会画出空白,值必须非空"""
        for name, body in self.sections.items():
            for key in REQUIRED:
                m = re.search(r'^ {12}"%s":\s*"(.*)",\s*$' % re.escape(key), body, re.M)
                self.assertIsNotNone(m, '%s 段 %s 不是普通字符串条目' % (name, key))
                self.assertTrue(m.group(1).strip(), '%s 段 %s 的值为空' % (name, key))

    def test_traditional_and_simplified_differ(self):
        """两套中文不能是复制粘贴:繁简必须是不同写法"""
        for key in REQUIRED:
            t = re.search(r'"%s":\s*"(.*)",' % key, self.sections[BASE]).group(1)
            s = re.search(r'"%s":\s*"(.*)",' % key, self.sections['simplified']).group(1)
            self.assertNotEqual(t, s, '%s 的繁简文案相同,疑似漏翻译' % key)


if __name__ == '__main__':
    unittest.main()
