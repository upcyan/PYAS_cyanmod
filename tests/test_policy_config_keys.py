"""策略存储契约:pyas_default 里的每个配置键必须在策略层登记。

背景:本 fork 全程跑在策略模式下(PolicyAccessMixin.update_config 对不在
POLICY_KEYS/USER_KEYS 白名单里的键直接拒绝并记 "Unknown configuration
field")。3.7.1-18 引入 etw_attribution_switch 时漏登记,2026-10-22 又因
behavior_defense_switch/behavior_auto_rollback 漏登记,用户设置页的进程
溯源/行为防护开关全部冻结 —— 点了没反应、被弹回。本契约让「新增配置键
忘登记策略 schema」直接挡构建,不再依赖记性。
"""

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def extract_default_keys():
    """用 AST 从 PYAS_Runtime.py 抽出 pyas_default 字面量字典的键与值类型。"""
    source = (ROOT / "PYAS_Runtime.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue

        targets = node.targets
        if (
            len(targets) == 1
            and isinstance(targets[0], ast.Attribute)
            and targets[0].attr == "pyas_default"
            and isinstance(node.value, ast.Dict)
        ):
            entries = {}

            for key_node, value_node in zip(node.value.keys, node.value.values):
                key = key_node.value  # 全部是字符串字面量
                entry_type = {
                    ast.Constant: "constant",
                }.get(type(value_node))

                if isinstance(value_node, ast.Constant):
                    entries[key] = type(value_node.value).__name__
                elif isinstance(value_node, ast.List):
                    entries[key] = "list"
                elif isinstance(value_node, ast.Dict):
                    entries[key] = "dict"
                else:
                    entries[key] = "expression"

            return entries

    raise AssertionError("PYAS_Runtime.py 里找不到 pyas_default 字面量字典,检查解析锚点")


class PolicyKeyContractTests(unittest.TestCase):
    # 启动时由代码覆写的运行时键:load_config 每次用 pyas_default 的值盖掉,
    # save_config 过滤时也不会落盘 —— 永远不需要用户/策略授权
    RUNTIME_MANAGED = frozenset({"version"})

    def setUp(self):
        self.defaults = extract_default_keys()
        self.assertTrue(self.defaults, "pyas_default 键抽取为空,检查解析")

    def test_every_default_key_is_registered(self):
        from PYAS_Policy import POLICY_KEYS, USER_KEYS

        problems = []
        for key in self.defaults:
            if key in self.RUNTIME_MANAGED:
                continue

            if key not in POLICY_KEYS and key not in USER_KEYS:
                problems.append(f"{key!r} 未登记策略 schema,应加入对应的 *_KEYS 或 USER_KEYS")

    def test_default_value_type_matches_registered_bucket(self):
        from PYAS_Policy import (
            BOOL_KEYS, LIST_KEYS, NUMBER_KEYS, POLICY_KEYS, STRING_KEYS, USER_KEYS,
        )

        problems = []
        for key, value_type in self.defaults.items():
            if key in USER_KEYS or key not in POLICY_KEYS:
                continue

            expected = {
                "bool": BOOL_KEYS, "str": STRING_KEYS, "int": NUMBER_KEYS,
                "float": NUMBER_KEYS, "list": LIST_KEYS,
            }.get(value_type)

            if expected is not None and key not in expected:
                problems.append(
                    f"{key!r} 默认值是 {value_type},却登记在别的桶里(应在对应的 *_KEYS)"
                )

        self.assertEqual(problems, [], "键的登记桶必须与默认值类型一致,否则策略校验会按错误类型对待")


if __name__ == "__main__":
    unittest.main()
