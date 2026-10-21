"""自启动权限路由测试:普通权限走 HKCU Run 注册表,管理员走提权计划任务。

背景:旧实现在普通权限下「开关打开但什么都没配」(提权任务需要管理员,
注册表路径又从未被使用),用户以为自启动生效了,实际开机不会运行。
现在普通权限必须真实写入 HKCU Run,与「启动项管理」页展示同源。
"""

import threading
import unittest
from unittest.mock import patch

from PYAS_Autostart import AutostartMixin

RUN_COMMAND = '"C:\\Program Files\\PYAS\\PYAS.exe" -hide'


class _Owner(AutostartMixin):
    """最小 owner:记录 write_log,注册表与提权探测全部由测试注入。"""

    def __init__(self, elevated):
        self.file_pyas = r"C:\Program Files\PYAS\PYAS.exe"
        self.autostart_mode = None
        self.logs = []
        self.lock_config = threading.RLock()
        self._elevated = elevated
        self.registry_calls = []
        self.registry_value = None
        self.disabled_tasks = []

    def _is_elevated(self):
        return self._elevated

    def _set_registry_autostart(self, enable):
        self.registry_calls.append(enable)

        if enable:
            self.registry_value = RUN_COMMAND

        return True

    def _get_registry_autostart(self):
        return self.registry_value

    def _get_autostart_user_sid(self):
        return "S-1-5-21-0-0-0-1001"

    def _elevated_task_exists(self, task_name):
        return self.task_exists

    def _disable_elevated_task_best_effort(self, task_name):
        self.disabled_tasks.append(task_name)
        return self.disable_ok

    def write_log(self, level, action, **kwargs):
        self.logs.append((level, action, kwargs))

    task_exists = False
    disable_ok = True


class RegistryFallbackTests(unittest.TestCase):
    def test_enable_writes_registry_and_logs_once(self):
        owner = _Owner(elevated=False)

        self.assertTrue(owner.manage_autostart(True))
        self.assertEqual(owner.registry_calls, [True])
        self.assertEqual(owner.autostart_mode, "registry")
        levels = [(level, kwargs.get("detail")) for level, _, kwargs in owner.logs]
        self.assertIn(("INFO", "Autostart configured via registry (HKCU Run)"), levels)

        # 启动复核:值已一致时保持静默,不再写注册表、不再刷日志
        owner.logs.clear()
        owner.registry_calls.clear()
        self.assertTrue(owner.manage_autostart(True))
        self.assertEqual(owner.registry_calls, [])
        self.assertEqual(owner.logs, [])

    def test_enable_mismatched_command_is_repaired(self):
        owner = _Owner(elevated=False)
        owner.registry_value = '"C:\\old\\PYAS.exe" -hide'

        self.assertTrue(owner.manage_autostart(True))
        self.assertEqual(owner.registry_calls, [True], "命令与当前安装位置不一致时必须重写")

    def test_disable_without_task_is_quiet_success(self):
        owner = _Owner(elevated=False)

        self.assertTrue(owner.manage_autostart(False))
        self.assertEqual(owner.registry_calls, [False])
        self.assertEqual(owner.autostart_mode, "disabled")
        self.assertTrue(all(level != "WARN" for level, _, _ in owner.logs),
            "没有提权任务时关闭就是普通成功,不该报 WARN")

    def test_disable_disables_leftover_elevated_task(self):
        owner = _Owner(elevated=False)
        owner.task_exists = True

        self.assertTrue(owner.manage_autostart(False))
        self.assertEqual(owner.disabled_tasks, ["PYAS_Security_ATS_S-1-5-21-0-0-0-1001"])
        details = [kwargs.get("detail") for _, _, kwargs in owner.logs]
        self.assertIn("Autostart disabled (registry entry removed; elevated task disabled)", details)

    def test_disable_warns_when_task_cannot_be_disabled(self):
        owner = _Owner(elevated=False)
        owner.task_exists = True
        owner.disable_ok = False

        self.assertTrue(owner.manage_autostart(False))
        warns = [kwargs.get("detail") for level, _, kwargs in owner.logs if level == "WARN"]
        self.assertEqual(warns,
            ["The elevated startup task could not be disabled without administrator rights"],
            "提权任务禁不掉必须如实报告,不能让用户以为已经关干净")

    def test_registry_failure_fails_the_switch(self):
        owner = _Owner(elevated=False)

        with patch.object(owner, "_set_registry_autostart", return_value=False):
            self.assertFalse(owner.manage_autostart(True))

        self.assertEqual(owner.autostart_mode, "unavailable")


class ElevatedPathTests(unittest.TestCase):
    def _owner(self):
        owner = _Owner(elevated=True)
        owner.powershell_script = None

        def fake_run_powershell(command, **kwargs):
            owner.powershell_script = command
            owner.run_calls = getattr(owner, "run_calls", 0) + 1
            return type("R", (), {"returncode": 0, "stdout": (
                '{"verified": true, "taskName": "PYAS_Security_ATS_S-1-5-21-0-0-0-1001",'
                ' "userSid": "S-1-5-21-0-0-0-1001", "enabled": true}'),
                "stderr": ""})()

        owner._run_powershell = fake_run_powershell
        return owner

    def test_elevated_enable_uses_task_script(self):
        owner = self._owner()

        self.assertTrue(owner.manage_autostart(True))
        self.assertEqual(owner.autostart_mode, "task")
        self.assertIsNotNone(owner.powershell_script)
        self.assertIn("Schedule.Service", owner.powershell_script)
        # 提权路径成功后要清掉旧的 HKCU Run 条目,避免双入口
        self.assertEqual(owner.registry_calls, [False],
            "task 配置成功后应移除注册表旧入口")


if __name__ == "__main__":
    unittest.main()
