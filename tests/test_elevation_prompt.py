"""提权说明弹窗的状态机:先说明后提权;确认记忆;取消不发起。"""

import sys
import threading
import unittest
import unittest.mock

sys.path.insert(0, ".")

from PYAS_ETW import EtwMixin


class PromptHost(EtwMixin):
    def __init__(self, config=None):
        self.lock_config = threading.RLock()
        self.pyas_config = config if config is not None else {
            "elevated_run_switch": True,
            "elevation_prompt_seen": False,
            "elevation_prompt_auto": True,
        }
        self.restored = []
        self.saved = 0
        self.logs = []

    def save_config(self):
        self.saved += 1
        return True

    def restore_switches(self, keys):
        self.restored.append(list(keys))

    def write_log(self, *args, **kwargs):
        self.logs.append((args, kwargs))

    def _loc(self, texts):
        return texts.get("simplified_switch") or next(iter(texts.values()))


class ElevationPromptTests(unittest.TestCase):
    def test_first_run_prompts_then_remembers(self):
        host = PromptHost()

        self.assertTrue(host._should_prompt_elevation(), "未确认过必须先弹说明")

        with unittest.mock.patch.object(
            host, "_ask_elevation_prompt", return_value=(True, True)
        ):
            host._auto_restore_for_privilege_run(["etw_attribution_switch"])

        self.assertEqual(host.restored, [["etw_attribution_switch"]], "确认后照常恢复")
        self.assertTrue(host.pyas_config["elevation_prompt_seen"])
        self.assertTrue(host.pyas_config["elevation_prompt_auto"])
        self.assertEqual(host.saved, 1)
        self.assertFalse(host._should_prompt_elevation(), "确认过且勾选自动后不再弹")

    def test_unchecked_remembers_ask_every_time(self):
        host = PromptHost()

        with unittest.mock.patch.object(
            host, "_ask_elevation_prompt", return_value=(True, False)
        ):
            host._auto_restore_for_privilege_run(["etw_attribution_switch"])

        self.assertTrue(host.pyas_config["elevation_prompt_seen"])
        self.assertFalse(host.pyas_config["elevation_prompt_auto"])
        self.assertTrue(host._should_prompt_elevation(), "取消勾选=每次都先说明")

    def test_decline_skips_restore_and_keeps_prompting(self):
        host = PromptHost()

        with unittest.mock.patch.object(
            host, "_ask_elevation_prompt", return_value=(False, True)
        ):
            host._auto_restore_for_privilege_run(["etw_attribution_switch"])

        self.assertEqual(host.restored, [], "取消后不得发起恢复/提权")
        self.assertFalse(host.pyas_config["elevation_prompt_seen"], "取消不记为已确认")
        self.assertTrue(host._should_prompt_elevation(), "下次启动仍先说明")

    def test_seen_and_auto_skip_prompt_entirely(self):
        host = PromptHost({
            "elevated_run_switch": True,
            "elevation_prompt_seen": True,
            "elevation_prompt_auto": True,
        })

        self.assertFalse(host._should_prompt_elevation())

        with unittest.mock.patch.object(host, "_ask_elevation_prompt") as ask:
            host._auto_restore_for_privilege_run(["etw_attribution_switch"])

        ask.assert_not_called()
        self.assertEqual(host.restored, [["etw_attribution_switch"]])


if __name__ == "__main__":
    unittest.main()
