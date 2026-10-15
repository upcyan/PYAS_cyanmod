"""「驱动防护状态不纳入警报」(driver_alert_exempt)的接线检查。

需求(2026-10-15,用户提出):
  1. 设置页要有这个开关,且默认开启;
  2. 开启后驱动防护未开启也不影响首页「此设备已受到防护」的判断;
  3. 关掉后回到原来的五灯口径(驱动不在=未完全开启)。

拆成两层:
  - 本文件管「接线」——默认值落在 pyas_default 里、设置页有独立 data-config-key 的行、
    首页判定真的读这个 key。静态检查,不需要起界面。
  - 「行为」由 tests/test_home_status_ui.cjs 用真浏览器覆盖(豁免开/关两种三态文案)。

注意 load_config 是 pyas_default 深拷贝后 update(用户配置),所以老配置即使没有这个 key
也会拿到默认值 —— 默认值必须写在 pyas_default,不能只写在界面上。
"""
import io
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNTIME = os.path.join(ROOT, 'PYAS_Runtime.py')
INDEX = os.path.join(ROOT, 'Interface', 'templates', 'index.html')
MAIN_JS = os.path.join(ROOT, 'Interface', 'static', 'js', 'main.js')

KEY = 'driver_alert_exempt'


def read(path):
    return io.open(path, encoding='utf-8').read()


def default_config_block(text):
    """截出 init_variables 里 self.pyas_default = { ... } 的文本"""
    start = text.index('self.pyas_default = {')
    end = text.index('\n        }', start)
    return text[start:end]


def window_block(text, window_id):
    """截出某个 <section id=...> 的内部文本(页面之间没有嵌套 section)"""
    start = text.index('id="%s"' % window_id)
    end = text.index('</section>', start)
    return text[start:end]


class DriverAlertExemptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = default_config_block(read(RUNTIME))
        cls.index = read(INDEX)
        cls.main = read(MAIN_JS)

    def test_default_is_on(self):
        """默认必须开:老配置由 load_config 合并默认值,默认关掉就等于功能没上"""
        m = re.search(r'"%s":\s*(\w+)' % KEY, self.defaults)
        self.assertIsNotNone(m, 'pyas_default 里没有 %s' % KEY)
        self.assertEqual(m.group(1), 'True', '%s 的默认值必须是 True' % KEY)

    def test_settings_row_exists_with_own_config_key(self):
        """要有独立开关,不能复用 driver_switch"""
        row = 'data-config-key="%s"' % KEY
        self.assertIn(row, self.index, '界面上没有 %s 的开关' % KEY)

    def test_row_lives_in_settings_not_protect(self):
        """开关属于「设置页」而不是「防护页」:它是界面偏好,不是某个防护模块的子开关

        挂在防护页会被读成「驱动防护的从属选项」,而它管的其实是首页怎么呈现状态。
        """
        row = 'data-config-key="%s"' % KEY
        self.assertIn(row, window_block(self.index, 'setting_window'),
                      '%s 应该在设置页' % KEY)
        self.assertNotIn(row, window_block(self.index, 'protect_window'),
                         '%s 不该留在防护页(已挪到设置页)' % KEY)

    def test_settings_row_text_is_translatable(self):
        """标题/说明走 data-i18n 显式 key,否则切语言时会退回中文"""
        for key in (KEY, KEY + '_desc'):
            self.assertIn('data-i18n="%s"' % key, self.index, '设置行缺少 data-i18n="%s"' % key)

    def test_home_status_reads_the_key(self):
        """首页三态判断必须真的读它,并且是把 driver 从判断集合里摘出去"""
        self.assertIn(KEY, self.main, '首页判定没有读 %s' % KEY)
        body = self.main[self.main.index('const updateProtectionLights'):]
        body = body[:body.index('\n    };')]
        self.assertRegex(body, r"filter\(\(?key\)?\s*=>\s*key\s*!==\s*'driver'\)",
                         '豁免逻辑应是「把 driver 从判断的键集合里去掉」')
        self.assertIn('driver_alert_exempt', body)

    def test_light_row_still_reflects_real_state(self):
        """驱动灯本身仍按真实开关显示(豁免只影响总述,不是把灯点亮)"""
        body = self.main[self.main.index('const updateProtectionLights'):]
        body = body[:body.index('\n    };')]
        self.assertRegex(body, r"PROTECT_LIGHT_KEYS\.forEach",
                         '灯的状态还是按 PROTECT_LIGHT_KEYS 全量刷新')


if __name__ == '__main__':
    unittest.main()
