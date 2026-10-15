"""重绘图标实装的护栏:内联 sprite、引用解析、描边契约、预览页一致性。

背景(2026-10-12):
界面图标从「每处内联一段 svg 几何」改成「内联整份 sprite + <use href="#i-xxx">」。
这套做法有几个只在运行时才暴露的失效点,本测试全部静态锁死:

  1. <use> 指向的 symbol 必须真的在同一个文档里(内联 sprite 漏了就会被静默渲染成空白)
  2. 各模板内联的 sprite 必须与 sprite.svg 逐字节一致(否则改了源文件界面不生效)
  3. 内联几何必须清干净(残留的旧几何会和新图标并存,层级上谁赢全看 CSS)
  4. JS 里动态拼的 <use> 也要能在 index.html 里解析到(main.js 的图标都在这个文档)
  5. 描边契约:symbol 用 var(--icon-stroke, 2) 取描边,列表图标上下文用 CSS 变量给 1.5。
     —— 外层 CSS 进不了 use 的 shadow,所以只能靠变量传,这两处必须成对存在
  6. 预览页内嵌的 symbol 与 sprite.svg 同源(评审用的「现状/重绘」对照不能失真)
"""
import io
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPRITE = os.path.join(ROOT, 'Interface', 'static', 'img', 'icons-redrawn', 'sprite.svg')
PREVIEW = os.path.join(ROOT, 'Interface', 'icons-preview.html')
INDEX = os.path.join(ROOT, 'Interface', 'templates', 'index.html')
THREAT = os.path.join(ROOT, 'Interface', 'templates', 'threat.html')
NOTIFY = os.path.join(ROOT, 'Interface', 'templates', 'notify.html')
MAIN_JS = os.path.join(ROOT, 'Interface', 'static', 'js', 'main.js')
STYLE = os.path.join(ROOT, 'Interface', 'static', 'css', 'style.css')

# 重绘集里没有对应图元、保持内联的两枚:关于按钮的信息圆、進程管理的显示器+心电。
# 每条为「该块必须包含的全部几何特征」,迁移时若给它们补了 symbol,这里应当同步收窄。
INLINE_ALLOWED = (
    ('circle cx="12" cy="12" r="10"', 'line x1="12" y1="16"', 'line x1="12" y1="8"'),
    ('<rect x="3" y="3" width="18" height="14" rx="2"', 'M8 21h8m-4-4v4M6 11h3l2-4 3 7 2-3h2'),
)


def read(path):
    return io.open(path, encoding='utf-8').read()


def symbols_of(text):
    """返回 {id: 整段 <symbol ...>...</symbol>(含开标签,便于校验属性)}"""
    return dict(re.findall(r'(<symbol id="(i-[a-z0-9-]+)"[^>]*>[\s\S]*?</symbol>)', text)
                and [(m[1], m[0]) for m in re.findall(r'(<symbol id="(i-[a-z0-9-]+)"[^>]*>[\s\S]*?</symbol>)', text)])


def uses_of(text):
    return re.findall(r'<use href="#(i-[a-z0-9-]+)"', text)


def inline_sprite_of(text):
    """取出模板里内联的那份 sprite(以 i-spinner 所在的那段 <svg> 为锚)"""
    m = re.search(r'(<svg xmlns="http://www\.w3\.org/2000/svg" style="display:none"[\s\S]*?</svg>)', text)
    return m.group(1) if m else ''


class IconInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sprite = read(SPRITE)
        cls.sprite_symbols = symbols_of(cls.sprite)

    def test_sprite_defines_expected_set(self):
        self.assertEqual(len(self.sprite_symbols), 52, '重绘集应为 52 个 symbol')
        self.assertIn('i-spinner', self.sprite_symbols)

    def test_every_use_resolves_in_same_document(self):
        """模板里的 <use> 必须都能在同文档内解析(漏 symbol = 静默空白)"""
        for path in (INDEX, THREAT, NOTIFY):
            text = read(path)
            defined = set(symbols_of(text))
            for used in sorted(set(uses_of(text))):
                self.assertIn(used, defined, '%s 引用了未定义的 %s' % (os.path.basename(path), used))

    def test_inlined_sprite_matches_source_file(self):
        """两个模板内联的 sprite 与 sprite.svg 必须一致,否则改源文件界面不生效"""
        for path in (INDEX, THREAT):
            block = inline_sprite_of(read(path))
            self.assertTrue(block, '%s 未内联 sprite' % os.path.basename(path))
            self.assertEqual(block, self.sprite.rstrip('\n'),
                             '%s 内联的 sprite 与 sprite.svg 不一致' % os.path.basename(path))

    def test_index_symbols_match_source(self):
        """index.html 文档内的每个 symbol 与源文件逐字符相同"""
        idx_symbols = symbols_of(read(INDEX))
        self.assertEqual(idx_symbols, self.sprite_symbols)

    def test_no_stale_inline_geometry(self):
        """内联几何已清干净:只允许白名单里的两枚保留"""
        text = read(INDEX)
        body = text[text.find('</svg>\n'):]  # 跳过内联 sprite 本体
        leftovers = re.findall(r'<svg\b[^>]*>\s*(?:(?!</svg>)[\s\S])*?</svg>', body)
        leftovers = [b for b in leftovers if re.match(r'<svg\b[^>]*>\s*<(?:path|rect|circle|line|polyline)', b)]
        for block in leftovers:
            matched = any(all(token in block for token in tokens) for tokens in INLINE_ALLOWED)
            self.assertTrue(matched, '残留内联几何未在允许清单内: %s' % re.sub(r'\s+', ' ', block)[:90])
        self.assertEqual(len(leftovers), len(INLINE_ALLOWED),
                         '保留的内联几何数量应为 %d,实际 %d' % (len(INLINE_ALLOWED), len(leftovers)))

    def test_spinner_uses_redrawn_animation(self):
        """加载动画改用 i-spinner(SMIL 自播),不再依赖 .path 类"""
        idx = read(INDEX)
        self.assertIn('class="spinner" aria-hidden="true" focusable="false"><use href="#i-spinner"/>', idx)
        style = read(STYLE)
        self.assertNotIn('.spinner .path', style, '旧的 .path 规则应已删除')
        self.assertNotIn('animation: dash', style, '旧的 dash 关键帧应已删除')
        self.assertIn('color: var(--text-secondary)', style, 'spinner 需给 currentColor 供色')

    def test_js_generated_uses_exist_in_index(self):
        """main.js 动态拼的 <use> 也要能在 index.html 解析到"""
        all_uses = uses_of(read(MAIN_JS))
        js_uses = sorted(set(all_uses))
        self.assertEqual(len(all_uses), 5, 'main.js 应有 5 处 <use>: %s' % js_uses)
        self.assertEqual(js_uses, ['i-chevron-down', 'i-close', 'i-copy', 'i-folder'],
                         'main.js 的图标集合变了: %s' % js_uses)
        defined = set(symbols_of(read(INDEX)))
        for used in sorted(js_uses):
            self.assertIn(used, defined, 'main.js 引用了 index.html 里没有的 %s' % used)

    def test_stroke_contract(self):
        """描边契约:symbol 用 var 取值,列表图标上下文用变量给 1.5(外层 CSS 进不了 shadow)"""
        for sid, body in self.sprite_symbols.items():
            if sid == 'i-spinner':
                continue
            m = re.search(r'stroke-width="([^"]*)"', body)
            self.assertIsNotNone(m, '%s 缺 stroke-width' % sid)
        var_count = sum(1 for sid, tag in self.sprite_symbols.items()
                        if sid != 'i-spinner' and 'stroke-width="var(--icon-stroke, 2)"' in tag)
        self.assertEqual(var_count, 51,
                         '除 i-spinner 外的 51 个 symbol 都应在 symbol 上用描边变量,实际 %d' % var_count)
        style = read(STYLE)
        self.assertIn('--icon-stroke: 1.5', style, '.item-icon 需用变量把描边传进 shadow')
        self.assertNotIn('stroke-width: 1.5', style, '对 use 无效的旧写法应已移除')

    def test_preview_symbols_match_sprite(self):
        """预览页内嵌 symbol 与 sprite.svg 同源(评审对照不失真)"""
        pv = symbols_of(read(PREVIEW))
        self.assertEqual(pv, self.sprite_symbols)
        for iid in ('i-plug', 'i-custom-shield', 'i-clock', 'i-reset', 'i-file-check'):
            self.assertIn(iid, pv)


if __name__ == '__main__':
    unittest.main()
