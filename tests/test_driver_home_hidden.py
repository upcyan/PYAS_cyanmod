"""「首页隐藏驱动防护状态」(driver_home_hidden)的接线检查。

需求(2026-10-19,用户提出):
  1. 「驱动防护状态不纳入警报」改名为「忽略驱动防护状态」;
  2. 它下面挂一个二级开关「首页隐藏驱动防护状态」,默认关闭;
  3. 开启后首页连驱动防护灯一起不显示。

为什么隐藏时还要从总述里摘掉:
  灯都看不见了,总述再拿它算一票,就会出现「其余四格全亮、文案却写未完全开启」,
  用户找不到是哪一格在拖后腿 —— 隐藏必须是「看见的口径」,不是只改 CSS。

本文件管「接线」:默认值、用户键白名单、界面层级、首页判定;
行为由 tests/test_home_status_ui.cjs 用真浏览器覆盖。
"""
import io
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNTIME = os.path.join(ROOT, 'PYAS_Runtime.py')
POLICY = os.path.join(ROOT, 'PYAS_Policy.py')
INDEX = os.path.join(ROOT, 'Interface', 'templates', 'index.html')
MAIN_JS = os.path.join(ROOT, 'Interface', 'static', 'js', 'main.js')
POLICY_JS = os.path.join(ROOT, 'Interface', 'static', 'js', 'policy.js')

KEY = 'driver_home_hidden'
PARENT = 'driver_alert_exempt'


def read(path):
    return io.open(path, encoding='utf-8').read()


def default_config_block(text):
    start = text.index('self.pyas_default = {')
    end = text.index('\n        }', start)
    return text[start:end]


def lights_body(text):
    body = text[text.index('const updateProtectionLights'):]
    return body[:body.index('\n    };')]


class DriverHomeHiddenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = default_config_block(read(RUNTIME))
        cls.index = read(INDEX)
        cls.main = read(MAIN_JS)

    def test_default_is_off(self):
        """默认必须关:老配置由 load_config 合并默认值,默认开等于功能自己先跑起来"""
        m = re.search(r'"%s":\s*(\w+)' % KEY, self.defaults)
        self.assertIsNotNone(m, 'pyas_default 里没有 %s' % KEY)
        self.assertEqual(m.group(1), 'False', '%s 的默认值必须是 False' % KEY)

    def test_is_user_key(self):
        """纯界面偏好,写进 USER_KEYS 才不会触发管理员授权(否则点一下开关就弹 UAC)"""
        block = read(POLICY)
        m = re.search(r'USER_KEYS = frozenset\(\{(.*?)\}\)', block, re.S)
        self.assertIsNotNone(m, 'PYAS_Policy.py 里找不到 USER_KEYS')
        self.assertIn("'%s'" % KEY, m.group(1), '%s 必须在 USER_KEYS 里' % KEY)

    def test_policy_panel_does_not_disable_it(self):
        """策略授权进行中,policy.js 会禁用所有配置项;用户偏好键要排除在外"""
        self.assertIn("'%s'" % KEY, read(POLICY_JS),
                      'policy.js 的 userKeys 没放行 %s' % KEY)

    def test_row_is_second_level_under_exempt(self):
        """必须是「忽略驱动防护状态」的二级行:自己的 data-config-key + data-setting-parent

        两处属性分属不同元素(父行 <div> / 子行 <input>),所以按「父行开标签到
        子行开关」这段标记整体匹配,不能按行找。
        """
        row = 'data-config-key="%s"' % KEY
        self.assertIn(row, self.index, '界面上没有 %s 的开关' % KEY)
        pattern = re.compile(
            r'<div class="list-item settings-child[^"]*"\s+data-setting-parent="%s">'
            r'.{0,600}?%s' % (PARENT, re.escape(row)), re.S)
        self.assertRegex(self.index, pattern,
                         '二级行必须挂 data-setting-parent="%s" 且自带开关' % PARENT)

    def test_row_text_is_translatable(self):
        for key in (KEY, KEY + '_desc'):
            self.assertIn('data-i18n="%s"' % key, self.index, '设置行缺少 data-i18n="%s"' % key)

    def test_home_hides_the_driver_light(self):
        body = lights_body(self.main)
        self.assertIn('light_driver', body, '首页判定没有动驱动灯')
        self.assertRegex(body, r"classList\.toggle\('hidden',\s*\w+\)",
                         '驱动灯应按 driver_home_hidden 切换 hidden')
        self.assertIn(KEY, body, '首页判定没有读 %s' % KEY)

    def test_hidden_driver_is_not_counted(self):
        """隐藏后不能再参与总述计数,否则会出现「看不见的那一格拖后腿」"""
        body = lights_body(self.main)
        self.assertRegex(body, r"counted\s*=\s*\w+\s*\?\s*judged\.filter\(\(key\)\s*=>\s*key\s*!==\s*'driver'\)",
                         '隐藏驱动灯时应从 judged 里再摘掉 driver')
        self.assertRegex(body, r"judgedOn\s*=\s*counted\.filter",
                         '计数必须用摘掉之后的集合')
        self.assertIn('counted.length', body, '满格判据必须跟着 counted')


if __name__ == '__main__':
    unittest.main()
