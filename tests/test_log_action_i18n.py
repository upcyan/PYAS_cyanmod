"""日志动作键的 i18n 契约:write_log 的动作字面量必须全部有界面词条。

背景:日志页动作列由前端 getMsg(动作原文) 查 i18n.js,详情列按写时本地化
渲染。历史上反复出现「新 write_log 忘补 i18n.js 键」,用户看到英文动作;
本契约让遗漏直接挡构建,不再依赖记性。
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LANGS = (
    "traditional_switch", "simplified_switch", "english_switch",
    "japanese_switch", "korean_switch", "french_switch", "spanish_switch",
    "hindi_switch", "arabic_switch", "russian_switch", "slovenian_switch",
)

# 动作字面量 = write_log( 的第二个实参(第一个是级别)
_STR = r'"((?:[^"\\]|\\.)*)"'
_CALL = re.compile(r"write_log\(\s*" + _STR + r"\s*,\s*" + _STR, re.S)


def i18n_blocks():
    js = (ROOT / "Interface" / "static" / "js" / "i18n.js").read_text(encoding="utf-8")
    blocks = {}

    for lang in LANGS:
        m = re.search(r'"' + lang + r'": \{\n(.*?)\n        \},', js, re.S)

        if m:
            blocks[lang] = dict(re.findall(r'"((?:[^"\\]|\\.)+)": "((?:[^"\\]|\\.)*)"', m.group(1)))

    return blocks


def code_action_literals():
    actions = {}

    for py in sorted(ROOT.glob("PYAS_*.py")):
        text = py.read_text(encoding="utf-8")

        for m in _CALL.finditer(text):
            actions.setdefault(m.group(2), set()).add(py.name)

    return actions


class LogActionI18nTests(unittest.TestCase):
    def setUp(self):
        self.blocks = i18n_blocks()

    def test_all_language_blocks_present(self):
        missing = [lang for lang in LANGS if lang not in self.blocks]
        self.assertEqual(missing, [], "i18n.js 语言块解析失败,先修解析锚点")

    def test_every_write_log_action_has_translation(self):
        actions = code_action_literals()
        self.assertTrue(actions, "未扫描到任何 write_log 动作字面量,检查正则")

        problems = []

        for action, files in sorted(actions.items()):
            for lang in LANGS:
                if action not in self.blocks[lang]:
                    problems.append(
                        f"{action!r} 缺 {lang} 词条 (写入点: {','.join(sorted(files))})"
                    )

        self.assertEqual(
            problems, [],
            "新 write_log 动作必须同步补入 i18n.js 全部 11 个语言块"
            "(动作列翻译由前端 getMsg(动作原文) 查得,缺键原样显示英文)",
        )

    def test_etw_log_texts_cover_all_languages(self):
        from PYAS_ETW import ETW_LOG_TEXTS

        problems = []

        for key, texts in ETW_LOG_TEXTS.items():
            for lang in LANGS:
                if not texts.get(lang):
                    problems.append(f"ETW_LOG_TEXTS[{key!r}] 缺 {lang}")

        self.assertEqual(problems, [], "写时本地化表必须 11 语种齐全,_loc 才不会回退繁体")
