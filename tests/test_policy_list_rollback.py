"""策略提交失败时,列表类改动必须从内存里退回。

背景(2026-10-19,用户上报):
  移除白名单 → UAC 授权通过 → 弹「策略授权或保存失败 … atomic policy replacement failed」,
  **但界面上那条记录确实消失了**。查下来是两层问题:
    1. broker 的 File.Replace 一直失败(PowerShell 把 $null 备份参数绑成空字符串,
       报 E_INVALIDARG;初始化走 Move 分支所以从没暴露);
    2. 提交失败后 PYAS_Threats 照样返回成功、内存里的列表也已经改掉 ——
       界面显示"已移除",磁盘(以及重启后的配置)还是旧值。
  第 1 层由 test_policy_native_contracts 的脚本契约覆盖,这里锁第 2 层。

只用假对象,不碰文件系统与管理员策略。
"""
import unittest

from PYAS_Threats import ThreatMixin


class _Lock:
    def __enter__(self): return self
    def __exit__(self, *exc): return False


class Recorder:
    """够 ThreatMixin 用的最小宿主:记录日志与驱动同步调用。"""

    lock_config = _Lock()

    def __init__(self, config, save_ok):
        self.pyas_config = config
        self.save_ok = save_ok
        self.logs = []
        self.driver = []

    def _loc(self, texts):
        return texts.get("simplified_switch") or next(iter(texts.values()))

    def norm_path(self, value, must_exist=False):
        if isinstance(value, (list, tuple)):
            return [self.norm_path(item, must_exist) for item in value]
        return str(value).replace('\\', '/')

    def write_log(self, level, action, detail='', success=True):
        self.logs.append((level, action, detail, success))

    def save_config(self):
        return self.save_ok

    def sync_driver_whitelist(self, path, is_add=True, is_directory=None):
        self.driver.append((path, is_add))

    def remove_list_items(self, list_key, paths):
        return False


class ListRollbackTests(unittest.TestCase):
    def test_remove_keeps_entry_when_commit_fails(self):
        entries = [{'file': 'C:/a.exe'}, {'file': 'C:/b.exe'}]
        owner = Recorder({'white_list': list(entries)}, save_ok=False)
        self.assertFalse(ThreatMixin.remove_list_items(owner, 'white_list', ['C:/a.exe']),
                         '提交失败必须返回 False,否则界面会当成成功')
        self.assertEqual(owner.pyas_config['white_list'], entries,
                         '磁盘上仍是旧列表,内存不能先斩后奏')
        self.assertEqual(owner.logs[-1][0], 'WARN', '失败要落 WARN 日志')
        self.assertEqual(owner.driver, [('C:/a.exe', False), ('C:/a.exe', True)],
                         '驱动规则先删后补,回到提交前状态')

    def test_remove_applies_when_commit_succeeds(self):
        owner = Recorder({'white_list': [{'file': 'C:/a.exe'}, {'file': 'C:/b.exe'}]}, save_ok=True)
        self.assertTrue(ThreatMixin.remove_list_items(owner, 'white_list', ['C:/a.exe']))
        self.assertEqual(owner.pyas_config['white_list'], [{'file': 'C:/b.exe'}])
        self.assertEqual(owner.logs[-1][0], 'INFO')

    def test_add_rolls_back_when_commit_fails(self):
        owner = Recorder({'white_list': []}, save_ok=False)
        self.assertEqual(ThreatMixin.manage_named_list(owner, 'white_list', ['C:/new.exe']), 0,
                         '失败时不能报"加入了 N 条"')
        self.assertEqual(owner.pyas_config['white_list'], [])
        self.assertEqual(owner.logs[-1][0], 'WARN')

    def test_add_applies_when_commit_succeeds(self):
        owner = Recorder({'white_list': []}, save_ok=True)
        self.assertEqual(ThreatMixin.manage_named_list(owner, 'white_list', ['C:/new.exe']), 1)
        self.assertEqual([item['file'] for item in owner.pyas_config['white_list']], ['C:/new.exe'])


if __name__ == '__main__':
    unittest.main()
