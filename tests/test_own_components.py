"""PYAS must not suspend its own components.

The launcher is the entry point of every start (shortcut, autostart, updater), so
a false positive there means the user sees a block dialog about PYAS itself the
moment they open the app. The exemption is deliberately narrow: only known names
inside the install directory.
"""
import os
from pathlib import Path
from unittest.mock import patch
import unittest

import build_launcher
import PYAS_Realtime as realtime

ROOT = Path(__file__).resolve().parents[1]
INSTALL = r'C:\Program Files\PYAS'


class OwnProcessImageTests(unittest.TestCase):
    def test_installed_components_are_recognised(self):
        for name in ('PYAS.exe', 'PYAS_Launcher.exe', 'PYAS_Menu.exe', 'pyas_launcher.exe'):
            with self.subTest(name=name):
                self.assertTrue(realtime.is_own_process_image(os.path.join(INSTALL, name), INSTALL))

    def test_same_name_outside_the_install_directory_is_not_exempt(self):
        # 同名文件放在下载目录不能靠名字蒙混过关
        other = r'C:\Users\someone\Downloads\PYAS_Launcher.exe'
        self.assertFalse(realtime.is_own_process_image(other, INSTALL))

    def test_unknown_binary_inside_the_install_directory_is_still_scanned(self):
        # 安装目录里出现陌生 exe 时不该顺带放行
        self.assertFalse(realtime.is_own_process_image(os.path.join(INSTALL, 'payload.exe'), INSTALL))

    def test_subdirectories_are_not_covered(self):
        # 只认同目录,不放行整棵子树
        nested = os.path.join(INSTALL, 'Engine', 'PYAS.exe')
        self.assertFalse(realtime.is_own_process_image(nested, INSTALL))

    def test_missing_inputs_are_never_treated_as_own(self):
        self.assertFalse(realtime.is_own_process_image('', INSTALL))
        self.assertFalse(realtime.is_own_process_image(os.path.join(INSTALL, 'PYAS.exe'), ''))


class WhitelistSeedTests(unittest.TestCase):
    def test_launcher_is_not_pushed_into_the_policy_whitelist(self):
        # white_list 是策略项:写进去要管理员授权,每次启动弹一次 UAC 不可接受。
        # 自身排除因此放在 is_own_process_image 里,而不是改白名单。
        text = (ROOT / 'PYAS_Protect.py').read_text(encoding='utf-8')
        start = text.index('def init_whitelist')
        end = text.index('def _driver_whitelist_patterns', start)
        body = text[start:end]
        self.assertNotIn('PYAS_Launcher.exe', body)


class SmokeSkipTests(unittest.TestCase):
    def test_probe_is_skipped_while_pyas_is_running(self):
        # 运行中的 PYAS 会暂停冒烟拉起的 launcher;这是防护正常,不是启动失败
        with patch.object(build_launcher, 'pyas_running', return_value=True), \
             patch.object(build_launcher.subprocess, 'Popen') as popen:
            build_launcher.smoke_launch(Path('does-not-matter'))
        self.assertEqual(popen.call_count, 0)

    def test_probe_still_runs_when_pyas_is_not_running(self):
        with patch.object(build_launcher, 'pyas_running', return_value=False):
            with self.assertRaises(RuntimeError):
                # 缺 PYAS.exe 时应报错,证明没有走 skip 分支
                build_launcher.smoke_launch(Path('definitely-missing'))


if __name__ == '__main__':
    unittest.main()
