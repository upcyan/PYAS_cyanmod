"""行为防护纯逻辑的约束:台账、快照路径、回滚决策(PowerShell/真 VSS 不在测试范围)。"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

from PYAS_ETW import BurstHeuristic
from PYAS_Behavior import (
    ACTION_ROLLBACK, MISS_PRUNE_ROUNDS, ROLLBACK_STAGING_DIRNAME, BehaviorMixin,
    TouchedFilesLedger, VssSnapshotManager, parse_vssadmin_shadows,
    parse_vssadmin_shadowstorage,
)

SNAP_DEVICE = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy9"


class LedgerTests(unittest.TestCase):
    def test_files_since_filters_stamp_and_drive_dedup(self):
        ledger = TouchedFilesLedger()
        ledger.record(7, "C:\\u\\a.docx", now=1.0)
        ledger.record(7, "C:\\u\\b.xlsx", now=2.0)
        ledger.record(7, "C:\\u\\a.docx", now=3.0)  # 重复改写,去重保留
        ledger.record(7, "D:\\other\\c.pdf", now=3.5)
        ledger.record(7, "C:\\old\\d.docx", now=0.5)  # 快照之前,应被过滤

        files = ledger.files_since(7, 1.0, "C:", now=10.0)

        # 顺序按最近一次改写(移到末尾),集合语义正确即可
        self.assertEqual(sorted(files), ["C:\\u\\a.docx", "C:\\u\\b.xlsx"])

    def test_capacity_evicts_oldest_paths_then_pids(self):
        ledger = TouchedFilesLedger(max_per_pid=2, max_pids=2)

        for index in range(5):
            ledger.record(1, f"C:\\f{index}.docx", now=1.0)

        self.assertEqual(len(ledger.files_since(1, 0.0, "C:", now=2.0)), 2)

        ledger.record(2, "C:\\x.docx", now=1.0)
        ledger.record(3, "C:\\y.docx", now=1.0)

        self.assertEqual(len(ledger), 2, "pid 数到顶必须淘汰最旧进程")

    def test_forget(self):
        ledger = TouchedFilesLedger()
        ledger.record(7, "C:\\a.docx", now=1.0)
        ledger.forget(7)

        self.assertEqual(ledger.files_since(7, 0.0, "C:", now=2.0), [])


class FakeVssRunner:
    """假 PowerShell:按调用序返回递增的快照设备;delete 调用留痕。"""

    def __init__(self, fail=False, error_text="vss broken"):
        self.calls = []
        self.deleted = []
        self.sequence = 0
        self.fail = fail
        self.error_text = error_text

    def __call__(self, script, result_file):
        self.calls.append(script)

        if "Remove-CimInstance" in script:
            match = __import__("re").search(r"ID='([^']+)'", script)
            self.deleted.append(match.group(1) if match else "?")
            return (True, "")

        self.sequence += 1

        if self.fail:
            content = self.error_text
        else:
            content = __import__("json").dumps({"id": f"shadow-id-{self.sequence}"})

        if result_file:
            with open(result_file, "w", encoding="utf-8") as f:
                f.write(content)

        return (not self.fail, "")


class FakeDeviceLister:
    """假 vssadmin 枚举:runner 发的每个序号 ID 都有对应设备路径。"""

    def __init__(self, mapping=None):
        self.mapping = mapping if mapping is not None else {
            f"shadow-id-{index}":
                "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" + str(index)
            for index in range(1, 32)
        }
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return dict(self.mapping)


class SnapshotManagerTests(unittest.TestCase):
    def make(self, tmp, **kwargs):
        kwargs.setdefault("device_lister", FakeDeviceLister())
        kwargs.setdefault("resolve_retries", 1)
        kwargs.setdefault("resolve_delay", 0.0)
        return VssSnapshotManager(
            state_path=str(Path(tmp) / "vss_snapshots.json"), **kwargs
        )

    def test_create_returns_device_and_replaces_old(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeVssRunner()
            manager = self.make(tmp, runner=runner, cooldown_seconds=60.0, history_keep=2)

            state, first = manager.create_if_due("C:", now=100.0)

            self.assertEqual(state, "created")
            self.assertTrue(first and first.endswith("ShadowCopy1"))
            self.assertEqual(manager.created_stamp("C:"), 100.0)
            self.assertEqual(manager.last_error, "")

            state, second = manager.create_if_due("C:", now=130.0)  # 冷却期内,复用

            self.assertEqual((state, second), ("existing", first))
            self.assertEqual(len(runner.calls), 1)

            state, third = manager.create_if_due("C:", now=200.0)  # 冷却结束,新建

            self.assertEqual(state, "created")
            self.assertTrue(third.endswith("ShadowCopy2"))
            self.assertEqual(manager.version_count("C:"), 2, "保留份数内不淘汰")
            self.assertEqual(runner.deleted, [], "未超保留份数不删除历史")

            state, fourth = manager.create_if_due("C:", now=300.0)  # 第 3 份:淘汰最旧

            self.assertEqual(state, "created")
            self.assertEqual(runner.deleted, ["shadow-id-1"], "超限淘汰最旧一份")
            self.assertEqual(manager.version_count("C:"), 2)
            self.assertEqual(manager.device_for("c:"), fourth)

    def test_failure_enters_cooldown_and_stays_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeVssRunner(fail=True)
            manager = self.make(tmp, runner=runner, cooldown_seconds=60.0)

            self.assertEqual(manager.create_if_due("C:", now=1.0), ("failed", None))
            # 冷却期内不重试也不重复报错;cim 与 wmi 两条路各跑一次
            self.assertEqual(manager.create_if_due("C:", now=30.0), ("cooldown", None))
            self.assertEqual(len(runner.calls), 2)

    def test_failure_sets_last_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeVssRunner(fail=True, error_text="VSS 拒绝访问")
            manager = self.make(tmp, runner=runner)

            state, device = manager.create_if_due("C:", now=1.0)

            self.assertEqual((state, device), ("failed", None))
            self.assertIn("拒绝访问", manager.last_error)

    def test_state_survives_restart_without_created_stamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeVssRunner()
            manager = self.make(tmp, runner=runner)
            manager.create_if_due("C:", now=1.0)

            revived = self.make(tmp, runner=FakeVssRunner())

            self.assertTrue(revived.device_for("C:"))
            self.assertIsNone(revived.created_stamp("C:"), "重启后时间基准失效,不可回滚")

    @staticmethod
    def seed_state(tmp, history):
        """直接写台账种子,模拟上个会话遗留的纳管快照。"""
        with open(Path(tmp) / "vss_snapshots.json", "w", encoding="utf-8") as f:
            json.dump({"C:": {"last_attempt": 0.0, "history": history}}, f)

    def test_missing_snapshot_prunes_after_consecutive_rounds(self):
        """失账 ID:首轮即告警,连续 MISS_PRUNE_ROUNDS 轮后消账,循环封顶。

        VSS 差异区满会正常淘汰最老副本,不消账则同一条失账每 5 分钟重告一次
        永不停止(2026-11-06 实测 C: 一条失账连刷 140+ 条 WARN)。
        """
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_state(tmp, [
                {"id": "shadow-id-1", "device": SNAP_DEVICE, "created_wall": 1.0},
                {"id": "shadow-id-stale", "device": SNAP_DEVICE + "x", "created_wall": 2.0},
            ])
            lister = FakeDeviceLister(mapping={"shadow-id-1": SNAP_DEVICE})
            manager = self.make(tmp, runner=FakeVssRunner(), device_lister=lister)

            for _ in range(MISS_PRUNE_ROUNDS - 1):
                result = manager.verify_snapshots_intact()

                self.assertEqual(result["missing"], ["C::shadow-id-stale"])
                self.assertEqual(result["pruned"], [], "未到轮数只告警不消账")

            result = manager.verify_snapshots_intact()

            self.assertEqual(result["pruned"], ["C::shadow-id-stale"], "连续确认到轮数即消账")
            self.assertNotIn(
                "shadow-id-stale",
                [item["id"] for item in manager._snapshots["C:"]["history"]],
                "消账后不再重告",
            )
            self.assertTrue(manager.device_for("C:"), "仍健在的快照不受影响")

            result = manager.verify_snapshots_intact()

            self.assertEqual((result["missing"], result["pruned"]), ([], []), "消账后循环终止")

    def test_miss_count_persists_across_restart(self):
        """轮数计数落盘:重启不重置,否则每次开机又重告满 3 轮。"""
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_state(tmp, [
                {"id": "shadow-id-stale", "device": SNAP_DEVICE, "created_wall": 1.0},
            ])
            lister = FakeDeviceLister(mapping={})
            manager = self.make(tmp, runner=FakeVssRunner(), device_lister=lister)

            result = manager.verify_snapshots_intact()

            self.assertEqual(result["missing"], ["C::shadow-id-stale"])
            self.assertEqual(result["pruned"], [])

            revived = self.make(tmp, runner=FakeVssRunner(), device_lister=lister)
            result = revived.verify_snapshots_intact()

            self.assertEqual(result["missing"], ["C::shadow-id-stale"])
            self.assertEqual(result["pruned"], [], "第 2 轮,继承重启前的计数")

            result = revived.verify_snapshots_intact()

            self.assertEqual(result["pruned"], ["C::shadow-id-stale"], "第 3 轮消账")

    def test_miss_count_resets_when_shadow_reappears(self):
        """失账 ID 重新出现在系统里:计数清零,重新从首轮数起。"""
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_state(tmp, [
                {"id": "shadow-id-1", "device": SNAP_DEVICE, "created_wall": 1.0,
                 "miss_count": MISS_PRUNE_ROUNDS - 1},
            ])
            lister = FakeDeviceLister(mapping={"shadow-id-1": SNAP_DEVICE})
            manager = self.make(tmp, runner=FakeVssRunner(), device_lister=lister)

            result = manager.verify_snapshots_intact()

            self.assertEqual(result["missing"], [], "重新在册即不算失账")

            lister.mapping.pop("shadow-id-1")
            result = manager.verify_snapshots_intact()

            self.assertEqual(result["missing"], ["C::shadow-id-1"])
            self.assertEqual(result["pruned"], [], "计数已清零,重新从首轮数起")

    def test_snapshot_path_math(self):
        self.assertEqual(
            VssSnapshotManager.snapshot_path(SNAP_DEVICE, "C:\\Users\\x\\a.doc"),
            SNAP_DEVICE + "\\Users\\x\\a.doc",
        )
        self.assertEqual(
            VssSnapshotManager.snapshot_path(SNAP_DEVICE, "C:\\a.doc"),
            SNAP_DEVICE + "\\a.doc",
        )

    def test_parse_vssadmin_shadowstorage_bilingual_and_unbounded(self):
        """存储占用解析:块内每卷出现两次盘符行(包含卷+存储卷)不得截断
        计数;无限制上限(无数值)回退 '-'。"""
        zh = (
            "vssadmin 1.1 - 卷影复制服务管理命令行工具\n"
            "(C) 版权所有 2001-2013 Microsoft Corp.\n"
            "\n"
            "卷影复制存储关联\n"
            "    包含卷影复制的卷: (C:)\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\\n"
            "        卷影复制存储卷: (C:)\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\\n"
            "        已使用的卷影复制存储空间: 20.4 GB (219,344,382,976 字节)\n"
            "        已分配的卷影复制存储空间: 339 MB (355,590,144 字节)\n"
            "        最大的卷影复制存储空间: 93.9 GB (10%)\n"
            "    包含卷影复制的卷: (D:)\\\\?\\Volume{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\\\n"
            "        卷影复制存储卷: (D:)\\\\?\\Volume{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\\\n"
            "        已使用的卷影复制存储空间: 1.5 GB\n"
            "        已分配的卷影复制存储空间: 2.0 GB\n"
            "        最大的卷影复制存储空间: 无限制\n"
        )
        rows = parse_vssadmin_shadowstorage(zh)
        self.assertEqual(len(rows), 2, "每卷两行盘符不得拆成两块")
        self.assertEqual(rows[0]["drive"], "C:")
        self.assertEqual(rows[0]["used"], "20.4 GB")
        self.assertEqual(rows[0]["allocated"], "339 MB")
        self.assertEqual(rows[0]["max"], "93.9 GB (10%)")
        self.assertEqual(rows[1]["drive"], "D:")
        self.assertEqual(rows[1]["used"], "1.5 GB")
        self.assertEqual(rows[1]["max"], "-", "无限制(无数值)应回退 '-'")

        en = (
            "Shadow Copy Storage association\n"
            "   For volume: (C:)\\\\?\\Volume{...}\\\n"
            "   Shadow Copy Storage volume: (C:)\\\\?\\Volume{...}\\\n"
            "   Used Shadow Copy Storage space: 5.1 GB (2%)\n"
            "   Allocated Shadow Copy Storage space: 5.4 GB\n"
            "   Maximum Shadow Copy Storage space: 264 GB (10%)\n"
        )
        rows_en = parse_vssadmin_shadowstorage(en)
        self.assertEqual(rows_en, [{
            "drive": "C:", "used": "5.1 GB", "allocated": "5.4 GB", "max": "264 GB (10%)",
        }])

    def test_unresolved_device_records_id_for_later_cleanup(self):
        """创建成功但设备名解析失败:ID 必须落盘 —— 否则快照成了
        无人纳管的孤儿(用户机器上已积累过 6 个),也无法在下次成功时删旧。"""
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeVssRunner()
            manager = self.make(tmp, runner=runner, device_lister=FakeDeviceLister(mapping={}),
                                history_keep=1)

            self.assertEqual(manager.create_if_due("C:", now=1.0), ("failed", None))
            self.assertIn("unresolved", manager.last_error)
            self.assertEqual(manager.drives(), [], "无设备路径的条目不可用于回滚")

            # 下一次创建成功时,孤儿 ID 被淘汰删除(keep=1:新份挤掉旧份)
            manager._device_lister = FakeDeviceLister()
            manager.create_if_due("C:", now=10000.0)
            self.assertEqual(runner.deleted, ["shadow-id-1"])

    def test_resolve_retries_until_listing_catches_up(self):
        """枚举滞后:第一次列表没有、重试后出现 —— 设备应解析成功。"""
        with tempfile.TemporaryDirectory() as tmp:
            lister = FakeDeviceLister()
            seen = {"n": 0}
            original = lister.__call__

            def flaky():
                seen["n"] += 1
                return {} if seen["n"] == 1 else original()

            manager = VssSnapshotManager(
                state_path=str(Path(tmp) / "vss_snapshots.json"),
                runner=FakeVssRunner(),
                device_lister=flaky,
                resolve_retries=3,
                resolve_delay=0.0,
            )

            state, device = manager.create_if_due("C:", now=1.0)

            self.assertEqual((state, device), ("created", lister.mapping["shadow-id-1"]))

    def test_inflight_create_collapses_second_caller(self):
        """并发护栏:创建进行中时,第二个调用按冷却处理,不触发 VSS 并行
        创建拒绝(实测 return=9)。"""
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeVssRunner()
            manager = self.make(tmp, runner=runner)

            manager._inflight["C:"] = 50.0

            self.assertEqual(manager.create_if_due("C:", now=100.0), ("cooldown", None))
            self.assertEqual(runner.calls, [], "护栏期内不得再发起创建")

    def test_stale_result_files_purged_on_init(self):
        """进程在创建中途退出会留下结果文件;超时的残留在下次初始化清掉。"""
        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp) / "pyas_vss_deadbeef.json"
            stale.write_text("{}", encoding="utf-8")
            two_hours_ago = time.time() - 7200.0
            os.utime(stale, (two_hours_ago, two_hours_ago))
            fresh = Path(tmp) / "pyas_vss_livestock.json"
            fresh.write_text("{}", encoding="utf-8")

            self.make(tmp)

            self.assertFalse(stale.exists())
            self.assertTrue(fresh.exists(), "进行中的创建结果不能被误删")

    def test_parse_vssadmin_shadows_locale_blind_pairing(self):
        """vssadmin 输出按系统语言本地化:只能信 GUID/设备 token。
        布局含集合 GUID 头与 \\?\Volume 行,配对必须只认卷影 ID。"""
        text = (
            "vssadmin 1.1 - 卷影复制服务管理命令行工具\n"
            "(C) 版权所有 2001-2013 Microsoft Corp.\n"
            "\n"
            "包含卷影副本集 ID: {11111111-2222-3333-4444-555555555555}\n"
            "   包含 1 个卷影副本\n"
            "   卷影副本 ID: {aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\n"
            "     卷: (C:)\\\\?\\Volume{99999999-8888-7777-6666-555555555555}\\\n"
            "     卷影副本卷: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy7\n"
            "     原始计算机名: DESKTOP\n"
            "\n"
            "   卷影副本 ID: {ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB}\n"
            "     卷: (D:)\\\\?\\Volume{12345678-1234-1234-1234-123456789012}\\\n"
            "     卷影副本卷: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy12\n"
        )

        devices = parse_vssadmin_shadows(text)

        self.assertEqual(
            devices,
            {
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee":
                    "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy7",
                "abcdefab-cdef-abcd-efab-cdefabcdefab":
                    "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy12",
            },
        )


class RollbackHost(BehaviorMixin):
    """最小宿主:只提供 BehaviorMixin 依赖的宿主面。"""

    def __init__(self, tmp, whitelist=()):
        self.lock_config = threading.RLock()
        self.pyas_config = {"behavior_defense_switch": True, "behavior_auto_rollback": True}
        self.path_config = tmp
        self._behavior_ledger = TouchedFilesLedger()
        self._behavior_l2 = BurstHeuristic(threshold=2, window_seconds=10.0, cooldown_seconds=60.0,
                                           pre_existing_seconds=0.0)
        self._vss = None
        self._behavior_switch_value = True
        self._behavior_switch_stamp = float("inf")
        self._behavior_auto_value = True
        self._behavior_auto_stamp = float("inf")
        self._whitelist = set(whitelist)
        self.logs = []

    def write_log(self, *args, **kwargs):
        self.logs.append((args, kwargs))

    def _loc(self, texts):
        return texts.get("simplified_switch") or next(iter(texts.values()))

    def is_in_whitelist(self, path):
        return path in self._whitelist

    def _spawn_behavior_worker(self, target, name):
        target()  # 测试内联执行,消除线程时序


class RollbackTests(unittest.TestCase):
    def prepare(self, tmp):
        """在临时目录里构造「快照卷 + 当前卷」的同构镜像。

        快照镜像必须与当前文件处于同一盘符的同一相对路径(回滚按卷内相对路径
        找快照副本),所以用临时目录的真实盘符,绝不能落到真实用户目录。
        """
        live = Path(tmp) / "live"
        rel = os.path.splitdrive(str(live))[1].lstrip("\\")
        drive = os.path.splitdrive(str(live))[0].upper()
        snap = Path(tmp) / "snap"

        (snap / rel / "Users").mkdir(parents=True)
        (snap / rel / "Users" / "a.docx").write_bytes(b"original-a")
        (snap / rel / "Users" / "b.docx").write_bytes(b"original-b")

        (live / "Users").mkdir(parents=True)
        (live / "Users" / "a.docx").write_bytes(b"encrypted-a")
        # b.docx 被删;c.docx 由攻击进程新建
        (live / "Users" / "c.docx").write_bytes(b"new-file")

        paths = {
            name: str(live / "Users" / f"{name}.docx") for name in ("a", "b", "c")
        }
        return snap, live, drive, paths

    def test_rollback_restores_quarantines_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap, live, drive, paths = self.prepare(tmp)
            host = RollbackHost(tmp)
            host._vss = type(
                "Stub", (), {"drives": staticmethod(lambda: [(drive, str(snap), 100.0)])}
            )()

            for name in ("a", "b", "c"):
                host._behavior_ledger.record(9, paths[name], now=100.0 + len(name))

            summary = host.rollback_process_writes(9, now=200.0)

            self.assertEqual(summary, {"restored": 2, "quarantined": 1, "skipped": 0, "failed": 0})
            self.assertEqual(
                Path(paths["a"]).read_bytes(), b"original-a", "被改写文件必须恢复为快照版本"
            )
            self.assertEqual(
                Path(paths["b"]).read_bytes(), b"original-b", "被删除文件必须从快照找回"
            )
            self.assertFalse(os.path.exists(paths["c"]), "新建文件必须移出原位")
            staging = Path(tmp) / "PYAS" / ROLLBACK_STAGING_DIRNAME
            quarantined = list(staging.rglob("c.docx"))
            self.assertEqual(len(quarantined), 1)
            self.assertEqual(quarantined[0].read_bytes(), b"new-file")

            # 回滚后台账清空,重复回滚是空操作
            again = host.rollback_process_writes(9, now=201.0)
            self.assertEqual(again["restored"], 0)

            actions = [args[1] for args, _ in host.logs]
            self.assertIn(ACTION_ROLLBACK, actions)

    def test_whitelisted_files_are_never_touched(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap, live, drive, paths = self.prepare(tmp)
            host = RollbackHost(tmp, whitelist={paths["a"]})
            host._vss = type(
                "Stub", (), {"drives": staticmethod(lambda: [(drive, str(snap), 100.0)])}
            )()

            host._behavior_ledger.record(9, paths["a"], now=101.0)
            host._behavior_ledger.record(9, paths["b"], now=101.0)

            summary = host.rollback_process_writes(9, now=200.0)

            self.assertEqual(summary["skipped"], 1)
            self.assertEqual(
                Path(paths["a"]).read_bytes(),
                b"encrypted-a",
                "白名单文件不能因启发式回滚被改写",
            )

    def test_pre_restart_snapshot_is_not_rolled_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap, live, drive, paths = self.prepare(tmp)
            host = RollbackHost(tmp)
            host._vss = type(
                "Stub", (), {"drives": staticmethod(lambda: [(drive, str(snap), None)])}
            )()
            host._behavior_ledger.record(9, paths["a"], now=1.0)

            summary = host.rollback_process_writes(9, now=2.0)

            self.assertEqual(summary["restored"], 0, "重启前的快照没有时间基准,绝不回滚")

    def test_l2_escalation_creates_snapshot_once_per_cooldown(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = RollbackHost(tmp)

            creations = []

            class StubVss:
                def create_if_due(self, drive, now=None):
                    creations.append((drive, now))

                    if len(creations) == 1:
                        return ("created", SNAP_DEVICE)

                    return ("cooldown", None)

            host._vss = StubVss()

            # 阈值 2:第一条不升级,第二条触发 L2
            host._behavior_on_write(9, "C:\\u\\a.docx", now=1.0)
            self.assertEqual(creations, [])

            host._behavior_on_write(9, "C:\\u\\b.xlsx", now=2.0)
            self.assertEqual(len(creations), 1)
            self.assertEqual(creations[0][0], "C:")

            # 冷却期内继续写:不再重复建快照
            host._behavior_on_write(9, "C:\\u\\c.pdf", now=3.0)
            self.assertEqual(len(creations), 1)

            logs = [args for args, _ in host.logs if args and args[1] == "Behavior Snapshot"]
            self.assertEqual(len(logs), 1, "成功建快照记一条 INFO,失败另记 WARN")

    def test_switch_off_disables_tracking(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = RollbackHost(tmp)
            host._behavior_switch_value = False

            host._behavior_on_write(9, "C:\\u\\a.docx", now=1.0)

            self.assertEqual(len(host._behavior_ledger), 0)
            self.assertEqual(len(host.logs), 0)

    def test_shadow_integrity_poll_delegates_to_snapshot_manager(self):
        """ScannerMixin.shadow_integrity_thread 调宿主的 verify_snapshots_intact。

        该方法曾只存在于 VssSnapshotManager 上,宿主没有 -> 轮询线程每轮
        AttributeError,完整性监控实际从未运行(2026-10-31 实测)。
        """
        with tempfile.TemporaryDirectory() as tmp:
            host = RollbackHost(tmp)
            sentinel = {"missing": ["D:deadbeef"]}
            stub = unittest.mock.Mock()
            stub.verify_snapshots_intact.return_value = sentinel
            host._ensure_vss_manager = lambda: setattr(host, "_vss", stub)

            self.assertEqual(host.verify_snapshots_intact(), sentinel)

    def test_shadow_integrity_works_before_any_snapshot_exists(self):
        """上个会话在册的卷影也要能巡检:懒创建管理器,而不是等首次建快照。"""
        with tempfile.TemporaryDirectory() as tmp:
            host = RollbackHost(tmp)

            result = host.verify_snapshots_intact()

            self.assertIsNotNone(host._vss, "管理器必须被懒创建")
            self.assertTrue(result is None or result == {"missing": [], "pruned": []},
                            "无在册快照时不得误报缺失")


if __name__ == "__main__":
    unittest.main()
