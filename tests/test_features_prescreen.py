# -*- coding: utf-8 -*-
"""PE 特征提取的输入预筛回归。

背景(2026-10-16 实况核对):目录/落盘扫描会把非 PE 文件(.txt / .log / 资源文件)一并送进
extract_features,交给 pefile 必然抛 PEFormatError——实测该类报错占该函数异常的 96/103
(`DOS Header magic not found` 96 条、`Unable to read the DOS Header` 7 条),
既把日志刷成噪音,又白烧解析 CPU。

修复:解析前先看 2 字节 MZ 头;有 MZ 但结构损坏/被截断的走 PEFormatError 静默分支。

本文件锁三件事:
  1. 非 PE 文件:静默返回 None,不记异常;
  2. 截断 PE:静默返回 None,不记异常;
  3. 真 PE 仍能正常出特征(防止预筛误杀) —— 这条是负向守卫。
"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import PYAS_Features
from PYAS_PE import PEScanner


class PrescreenTests(unittest.TestCase):
    def setUp(self):
        # 用真实组合类(常量 _OPTIONAL_HEADER_FIELDS/_SECTION_DEFAULTS 定义在 PEScanner 上,
        # 裸 PEFeatureMixin 缺这些常量,会在 _base_defaults 处抛 AttributeError 干扰断言)
        self.mixin = PEScanner()
        self.tmp = tempfile.mkdtemp(prefix="pyas_pe_")
        self.logged = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data):
        path = os.path.join(self.tmp, name)

        with open(path, "wb") as handle:
            handle.write(data)

        return path

    def _extract(self, path):
        with patch.object(
            PYAS_Features, "log_exception",
            side_effect=lambda *args, **kwargs: self.logged.append(args),
        ):
            return self.mixin.extract_features(path)

    def test_non_pe_file_skipped_silently(self):
        """纯文本文件:返回 None、零异常日志,且**绝不进 pefile 解析**(省 CPU 的不变量)"""
        path = self._write("note.txt", b"hello pyas\n" * 40)

        with patch.object(PYAS_Features.pefile, "PE") as fake_pe:
            result = self._extract(path)

        self.assertIsNone(result)
        self.assertEqual(self.logged, [], "非 PE 文件不该产生异常日志")
        fake_pe.assert_not_called()  # 只靠 PEFormatError 兜住也能不报错,但会白解析一遍

    def test_truncated_pe_skipped_silently(self):
        """有 MZ 头但结构损坏:pefile 会抛 PEFormatError → 走静默分支,不记异常"""
        path = self._write("broken.exe", b"MZ" + b"\x00" * 30)

        with patch.object(PYAS_Features.pefile, "PE",
                          side_effect=PYAS_Features.pefile.PEFormatError("truncated")):
            result = self._extract(path)

        self.assertIsNone(result)
        self.assertEqual(self.logged, [], "截断 PE 属扫描噪音,不该记异常")

    def test_real_pe_still_extracted(self):
        """负向守卫:真 PE 必须仍能出特征,预筛不能误杀"""
        dll = os.path.join(
            os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "version.dll")
        self.assertTrue(os.path.isfile(dll), f"测试依赖的真实 PE 不存在: {dll}")

        result = self._extract(dll)

        self.assertIsNotNone(result, "真 PE 被预筛误杀了")
        self.assertIn("Base", result)
        self.assertGreater(result["Base"].get("ImportCount", 0.0), 0.0)
        self.assertEqual(self.logged, [], f"真 PE 解析不该报错: {self.logged[:1]}")

    def test_empty_and_oversized_guards_unchanged(self):
        """原有边界仍在:空文件直接返回;不存在的路径仍按异常路径上报(不静默吞)"""
        self.assertIsNone(self._extract(self._write("empty.bin", b"")))
        self.assertEqual(self.logged, [], "空文件是正常边界,不该记异常")

        self.assertIsNone(self._extract(os.path.join(self.tmp, "nope.exe")))
        self.assertEqual(len(self.logged), 1, "读不到的路径应仍按异常上报,便于排查")


if __name__ == "__main__":
    unittest.main()
