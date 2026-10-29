"""ETW 消费者纯逻辑部分的行为约束(OS 调用与会话启动不在测试范围)。"""

import sys
import unittest
import uuid

import PYAS_ETW as etw


class GuidTests(unittest.TestCase):
    def test_guid_matches_provider(self):
        guid = etw.guid_from_text(etw.KERNEL_FILE_PROVIDER)

        self.assertTrue(etw.guid_matches(guid, etw.KERNEL_FILE_PROVIDER))
        self.assertFalse(
            etw.guid_matches(guid, "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")
        )

    def test_guid_memory_layout_is_bytes_le(self):
        guid = etw.guid_from_text(etw.KERNEL_FILE_PROVIDER)

        self.assertEqual(bytes(guid), uuid.UUID(etw.KERNEL_FILE_PROVIDER).bytes_le)


class SubscribeModelTests(unittest.TestCase):
    def test_keyword_mask_covers_write_path_events(self):
        # 写入/创建/改名/删除的关键字位必须全部在订阅掩码里;
        # READ(0x100) 绝不能进掩码,否则事件量涨两个数量级
        self.assertEqual(etw.SUBSCRIBE_KEYWORDS, 0x1E90)
        self.assertEqual(etw.SUBSCRIBE_KEYWORDS & 0x100, 0, "READ 关键字位绝不能进订阅掩码")

    def test_write_events_in_handler_set(self):
        for event_id in (
            etw.EVT_NAME_CREATE, etw.EVT_CREATE, etw.EVT_WRITE,
            etw.EVT_DELETE_PATH, etw.EVT_RENAME_PATH, etw.EVT_SETLINK_PATH,
        ):
            self.assertIn(event_id, etw.HANDLED_EVENT_IDS)

    def test_available_reason_codes(self):
        if not sys.platform == "win32":
            self.assertEqual(etw.available(), (False, "unsupported-platform"))
        elif etw.is_elevated():
            self.assertEqual(etw.available(), (True, "ok"))
        else:
            self.assertEqual(etw.available(), (False, "elevated-required"))


class NtPathTests(unittest.TestCase):
    def test_longest_device_prefix_wins(self):
        mapping = {
            "\\Device\\HarddiskVolume3": "C:",
            "\\Device\\HarddiskVolume30": "D:",
        }

        self.assertEqual(
            etw.nt_to_dos("\\Device\\HarddiskVolume30\\Users\\a.dll", mapping),
            "D:\\Users\\a.dll",
        )
        self.assertEqual(
            etw.nt_to_dos("\\Device\\HarddiskVolume3\\Users\\a.dll", mapping),
            "C:\\Users\\a.dll",
        )

    def test_unknown_device_passthrough(self):
        self.assertEqual(etw.nt_to_dos("\\Device\\Mup\\srv\\share\\x.exe", {}), "\\Device\\Mup\\srv\\share\\x.exe")

    def test_dos_path_untouched(self):
        self.assertEqual(etw.nt_to_dos("C:\\x\\y.dll", {}), "C:\\x\\y.dll")


class BurstHeuristicTests(unittest.TestCase):
    def make(self, **kwargs):
        # pre_existing 默认关闭:本组测试滑窗/冷却/容量语义,pre-existing
        # 单独在 PreExistingTests 里覆盖
        defaults = dict(threshold=3, window_seconds=10.0, cooldown_seconds=60.0,
                        pre_existing_seconds=0.0)
        defaults.update(kwargs)
        return etw.BurstHeuristic(**defaults)

    def test_fires_at_threshold_with_distinct_files(self):
        h = self.make()

        self.assertIsNone(h.record(100, "C:\\u\\a.docx", now=1.0))
        self.assertIsNone(h.record(100, "C:\\u\\b.xlsx", now=2.0))
        alert = h.record(100, "C:\\u\\c.pdf", now=3.0)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.pid, 100)
        self.assertEqual(alert.count, 3)
        self.assertEqual(len(alert.samples), 3)

    def test_same_file_rewrites_count_once(self):
        h = self.make()

        for stamp in (1.0, 2.0, 3.0):
            self.assertIsNone(h.record(100, "C:\\u\\a.docx", now=stamp))

    def test_cooldown_suppresses_repeat_alerts(self):
        h = self.make()

        self.assertIsNone(h.record(100, "C:\\u\\f0.docx", now=1.0))
        self.assertIsNone(h.record(100, "C:\\u\\f1.docx", now=2.0))
        self.assertIsNotNone(h.record(100, "C:\\u\\f2.docx", now=3.0))

        # 冷却期内再次到达阈值:不再重复告警
        for index in range(3):
            self.assertIsNone(h.record(100, f"C:\\u\\h{index}.docx", now=6.0 + index))

        # 冷却期过后,新一轮突发照常告警
        self.assertIsNone(h.record(100, "C:\\u\\late0.docx", now=63.0))
        self.assertIsNone(h.record(100, "C:\\u\\late1.docx", now=64.0))
        self.assertIsNotNone(h.record(100, "C:\\u\\late2.docx", now=65.0))

    def test_window_expiry_resets_count(self):
        h = self.make()

        for index in range(3):
            h.record(100, f"C:\\u\\f{index}.docx", now=1.0 + index)

        # 窗口外重新开始:旧事件过期,不告警
        self.assertIsNone(h.record(100, "C:\\u\\late.docx", now=100.0))

    def test_pids_are_isolated(self):
        h = self.make()

        for index in range(3):
            h.record(100, f"C:\\u\\f{index}.docx", now=1.0 + index)

        self.assertIsNone(h.record(200, "C:\\u\\other.docx", now=4.0))

    def test_non_target_extension_ignored(self):
        h = self.make()

        for index in range(10):
            self.assertIsNone(h.record(100, f"C:\\build\\obj{index}.obj", now=1.0 + index))

        # 文档混进来时才计入
        self.assertIsNone(h.record(100, "C:\\u\\doc.docx", now=11.0))

    def test_capacity_bounded_and_old_pid_evicted(self):
        h = self.make(threshold=999, max_pids=2)

        h.record(1, "C:\\a.docx", now=1.0)
        h.record(2, "C:\\a.docx", now=1.0)
        h.record(3, "C:\\a.docx", now=1.0)

        self.assertEqual(len(h), 2)

    def test_delete_events_count_toward_burst(self):
        # 加密流程常伴随删除原文件:删除必须与写入走同一计数
        watcher = etw.EtwFileWatcher()
        watcher._apply_event(etw.EVT_DELETE_PATH, 100, "C:\\u\\x.docx", 11, 22, 0, 1.0)

        self.assertEqual(watcher.stats["delete"], 1)


class PreExistingTests(unittest.TestCase):
    """pre-existing 过滤:只有会话早期已存在的文档才计入突发。

    实测根因:该参数曾只有声明没有实现,OneDriveSetup 解包资源、
    Edge 落扩展图标这类全新文件风暴直接撞满阈值。
    """

    def make(self, **kwargs):
        defaults = dict(threshold=3, window_seconds=10.0, cooldown_seconds=60.0,
                        pre_existing_seconds=30.0)
        defaults.update(kwargs)
        return etw.BurstHeuristic(**defaults)

    def test_fresh_files_never_count(self):
        h = self.make()

        for index in range(10):
            self.assertIsNone(h.record(100, f"C:\\pkg\\res{index}.png", now=100.0 + index),
                              "首次出现的文件不得计入突发")

    def test_existing_file_counts_after_delay(self):
        h = self.make()

        # 首次出现只登记:不计数
        self.assertIsNone(h.record(100, "C:\\u\\a.docx", now=1.0))
        self.assertIsNone(h.record(100, "C:\\u\\b.docx", now=2.0))
        self.assertIsNone(h.record(100, "C:\\u\\c.docx", now=3.0))

        # 距首次出现 ≥30 秒的改写才计入突发
        self.assertIsNone(h.record(100, "C:\\u\\a.docx", now=31.0))
        self.assertIsNone(h.record(100, "C:\\u\\b.docx", now=32.0))
        alert = h.record(100, "C:\\u\\c.docx", now=33.0)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.count, 3)

    def test_write_within_preexisting_window_delays_counting(self):
        h = self.make()

        # 20 秒首见(不计数);45 秒改写距首次仅 25s,仍不计
        self.assertIsNone(h.record(100, "C:\\u\\a.docx", now=20.0))
        self.assertIsNone(h.record(100, "C:\\u\\a.docx", now=45.0))

        # 另两个文件先预热,55 秒后同一窗口内改写即计入
        self.assertIsNone(h.record(100, "C:\\u\\b.docx", now=21.0))
        self.assertIsNone(h.record(100, "C:\\u\\c.docx", now=22.0))
        self.assertIsNone(h.record(100, "C:\\u\\a.docx", now=55.0))
        self.assertIsNone(h.record(100, "C:\\u\\b.docx", now=56.0))
        alert = h.record(100, "C:\\u\\c.docx", now=57.0)

        self.assertIsNotNone(alert, "距首次出现 35 秒的改写应计入并触发")


class PointerMapTests(unittest.TestCase):
    def test_set_get_roundtrip_and_ttl(self):
        m = etw.PointerMap(ttl_seconds=10.0, max_entries=4)

        m.set(0x1000, "C:\\a.dll", now=1.0)
        self.assertEqual(m.get(0x1000, 2.0), "C:\\a.dll")
        self.assertIsNone(m.get(0x1000, 12.0), "TTL 过期必须失效")
        self.assertIsNone(m.get(0, 2.0), "空指针直接判未命中")

    def test_capacity_evicts_oldest(self):
        m = etw.PointerMap(max_entries=2)

        m.set(1, "C:\\1.dll", now=1.0)
        m.set(2, "C:\\2.dll", now=1.0)
        m.set(3, "C:\\3.dll", now=1.0)

        self.assertEqual(len(m), 2)
        self.assertIsNone(m.get(1, 1.5))
        self.assertEqual(m.get(3, 1.5), "C:\\3.dll")


class PidInfoCacheTests(unittest.TestCase):
    def test_resolves_once_and_caches(self):
        calls = []

        def resolver(pid):
            calls.append(pid)
            return (f"proc{pid}.exe", f"C:\\bin\\proc{pid}.exe")

        cache = etw.PidInfoCache(resolver)

        self.assertEqual(cache.get(7), ("proc7.exe", "C:\\bin\\proc7.exe"))
        self.assertEqual(cache.get(7), ("proc7.exe", "C:\\bin\\proc7.exe"))
        self.assertEqual(calls, [7])

    def test_resolver_failure_returns_empty(self):
        def boom(pid):
            raise OSError("gone")

        cache = etw.PidInfoCache(boom)

        self.assertEqual(cache.get(9), ("", ""))

    def test_no_resolver_returns_empty(self):
        self.assertEqual(etw.PidInfoCache(None).get(9), ("", ""))


class RecycleBinExclusionTests(unittest.TestCase):
    """回收站是用户主动清空的操作:写/删事件不得进溯源缓存、行为台账与
    勒索启发(实测一次清空即 explorer.exe 连续 6 次勒索误报)。"""

    def make_host(self):
        import threading

        class _Host(etw.EtwMixin):
            def __init__(self):
                self.lock_config = threading.RLock()
                self.pyas_config = {"suffix": [".docx"]}
                self._etw_suffix_stamp = 0.0
                self._etw_suffixes = frozenset()
                self._etw_pid_info = etw.PidInfoCache(None)
                self._etw_heuristic = etw.BurstHeuristic(
                    threshold=2, window_seconds=10.0, cooldown_seconds=60.0,
                    pre_existing_seconds=0.0
                )
                self.reached = []
                self.whitelisted = set()
                # 程序区域豁免依赖写入方签名;测试按 pid 注入信任
                self.trusted_pids = {700}

            def _etw_writer_trusted(self, pid):
                return pid in self.trusted_pids

            def _behavior_on_write(self, pid, path):
                self.reached.append(path)

            def _behavior_maybe_rollback(self, pid):
                self.reached.append(f"rollback:{pid}")

            def write_log(self, *args, **kwargs):
                self.reached.append(("log", args, kwargs))

            def dispatch_notification(self, *args, **kwargs):
                pass

            def _loc(self, texts):
                return texts.get("simplified_switch") or ""

            def is_in_whitelist(self, path):
                return path in self.whitelisted

        return _Host()

    def test_recycle_bin_write_and_delete_fully_ignored(self):
        host = self.make_host()

        host._on_etw_write(700, "C:\\$Recycle.Bin\\S-1-5-21\\$R7.docx")
        host._on_etw_delete(700, "C:\\$RECYCLE.BIN\\S-1-5-21\\$R8.docx")

        self.assertEqual(host.reached, [], "回收站路径不得触达台账/告警/回滚")

    def test_normal_path_still_dispatched(self):
        host = self.make_host()

        host._on_etw_write(700, "C:\\Users\\u\\a.docx")

        self.assertEqual(host.reached, ["C:\\Users\\u\\a.docx"])

    def test_whitelisted_path_never_fires_burst_alert(self):
        """白名单必须同时管住 L3:QQ/微信数据目录加白后不再弹勒索告警,
        也不再因告警触发紧急快照(此前行为层跳过、告警层照弹)。"""
        host = self.make_host()
        host.whitelisted = {"D:\\Tencent\\nt_qq\\Pic\\Thumb\\1.jpg"}

        host._on_etw_write(700, "D:\\Tencent\\nt_qq\\Pic\\Thumb\\1.jpg")
        host._on_etw_write(700, "D:\\Tencent\\nt_qq\\Pic\\Thumb\\2.jpg")

        self.assertEqual(
            [r for r in host.reached if isinstance(r, tuple) and r[0] == "log"],
            [],
            "白名单路径不得触发勒索告警/回滚",
        )

    def test_im_cache_dirs_are_noise_by_default(self):
        """IM 聊天数据目录(QQ NT/微信)的缓存改写不进启发:用户没加白名单
        也不得误报(实测 QQ nt_qq Pic/Ori 与 nt_temp tile_files 撞满阈值)。"""
        host = self.make_host()

        host._on_etw_write(700, "D:\\Personal\\Documents\\Tencent Files\\354723161\\nt_qq\\nt_data\\Pic\\2026-10\\Ori\\0b1c67572f3afcffe2529cf4cf75ee1c.png")
        host._on_etw_write(700, "D:\\Personal\\Documents\\Tencent Files\\354723161\\nt_qq\\nt_temp\\7701236535243825943_7701236535243825942\\tile_files\\12\\7_0.jpeg")
        host._on_etw_write(700, "C:\\Users\\u\\xwechat_files\\abc\\msg\\attach\\thumb.jpg")
        host._on_etw_write(700, "D:\\Legacy\\WeChat Files\\wx\\FileStorage\\a.jpg")

        self.assertEqual(host.reached, [], "IM 缓存目录默认即噪音,不触达台账/告警")

    def test_programdata_never_fires_burst_but_keeps_ledger(self):
        """ProgramData 是全部安装软件的机器级数据目录:安全软件诱饵(实测
        腾讯 iOA DecoyFiles 触发勒索启发)、同步盘数据库都在此高频改写。
        突发计数必须豁免;台账保留,回滚能力不受影响。"""
        host = self.make_host()

        host._on_etw_write(700, "C:\\ProgramData\\ZtsmEnt\\EPSecDoc\\DecoyFiles\\IndexPhyFiles_000.txt")
        host._on_etw_write(700, "C:\\ProgramData\\ZtsmEnt\\EPSecDoc\\DecoyFiles\\IndexPhyFiles_001.txt")

        self.assertEqual(
            [r for r in host.reached if isinstance(r, tuple) and r[0] == "log"],
            [], "ProgramData 不得触发勒索告警",
        )
        self.assertEqual(
            host.reached,
            [
                "C:\\ProgramData\\ZtsmEnt\\EPSecDoc\\DecoyFiles\\IndexPhyFiles_000.txt",
                "C:\\ProgramData\\ZtsmEnt\\EPSecDoc\\DecoyFiles\\IndexPhyFiles_001.txt",
            ],
            "台账必须照常记录,回滚不受豁免影响",
        )

    def test_program_area_by_segment_name_any_drive(self):
        """程序区域按段名判定,不绑定 C 盘:用户把游戏库装在
        E:\\Program Files\\games\\(实测 Steam 下载 chunk 触发勒索启发),
        任意盘符的 Program Files/Windows/WindowsApps 都是程序区域。"""
        host = self.make_host()

        host._on_etw_write(700, "E:\\Program Files\\games\\steam\\steamapps\\downloading\\1551360\\media\\Audio\\EngineSynth\\D_I4TC_European_Offroad_1_Exh.zip")
        host._on_etw_write(700, "E:\\Program Files (x86)\\SomeApp\\data.bin")
        host._on_etw_write(700, "D:\\Windows\\Temp\\cache.dat")
        host._on_etw_write(700, "D:\\Games\\Steam\\steamapps\\downloading\\chunk_0.zip")

        self.assertEqual(
            [r for r in host.reached if isinstance(r, tuple) and r[0] == "log"],
            [], "任意盘符的程序/内容目录不得触发勒索告警",
        )
        self.assertTrue(host.reached, "台账照常记录")

    def test_user_documents_still_fire_after_segment_exclusion(self):
        """段名排除不得误伤用户文档区:勒索的主战场必须保持告警能力。"""
        host = self.make_host()

        host._on_etw_write(700, "D:\\Personal\\Documents\\a.docx")
        host._on_etw_write(700, "C:\\Users\\u\\Desktop\\b.docx")
        host._on_etw_write(700, "E:\\MyDocs\\Games\\notes.docx")

        logs = [r for r in host.reached if isinstance(r, tuple) and r[0] == "log"]
        self.assertEqual(len(logs), 1, "用户文档照常计数并在阈值处告警一次")

    def test_program_area_unsigned_writer_still_fires(self):
        """段名只是必要条件:程序区域里的写入方若无受信任签名,照常计数 ——
        堵住「在 Program Files 里加密文档」的漏检通道(fail-closed)。"""
        host = self.make_host()
        host.trusted_pids = set()  # 写入方未签名/验证失败

        host._on_etw_write(700, "C:\\Program Files\\Victim\\a.docx")
        host._on_etw_write(700, "C:\\Program Files\\Victim\\b.docx")

        logs = [r for r in host.reached if isinstance(r, tuple) and r[0] == "log"]
        self.assertEqual(len(logs), 1, "程序区域+未签名写入方必须照常告警")

    def test_program_area_trusted_writer_exempt(self):
        """签名受信的写入方在程序区域的自有内容写入豁免(Steam 下载/
        安装器解包),不再误报。"""
        host = self.make_host()

        for index in range(5):
            host._on_etw_write(700, f"E:\\Program Files\\games\\steam\\steamapps\\downloading\\chunk_{index}.zip")

        self.assertEqual(
            [r for r in host.reached if isinstance(r, tuple) and r[0] == "log"],
            [], "签名可信写入方在程序区域不得触发勒索告警",
        )

    def test_burst_alert_detail_carries_sample_paths(self):
        """告警明细必须带样本路径:否则 svchost/QQ 类误报只能看到进程名,
        定位写入目标要靠全盘扫描。"""
        host = self.make_host()

        host._on_etw_write(700, "C:\\Users\\u\\a.docx")
        host._on_etw_write(700, "C:\\Users\\u\\b.docx")

        logs = [r for r in host.reached if isinstance(r, tuple) and r[0] == "log"]

        self.assertEqual(len(logs), 1, "阈值 2:两条不同文档应告警一次")
        detail = logs[0][2].get("detail") or ""
        self.assertIn("C:\\Users\\u\\a.docx", detail)
        self.assertIn("C:\\Users\\u\\b.docx", detail)


class WatcherEventFlowTests(unittest.TestCase):
    """句柄关联的核心流程:NameCreate/Create 建表 → Write 反查 → 回调 DOS 路径。"""

    def make_watcher(self):
        writes, deletes = [], []
        watcher = etw.EtwFileWatcher(
            on_write=lambda pid, path: writes.append((pid, path)),
            on_delete=lambda pid, path: deletes.append((pid, path)),
        )
        return watcher, writes, deletes

    def test_name_create_then_write_resolves_path(self):
        from unittest.mock import patch

        watcher, writes, _ = self.make_watcher()
        now = 10.0

        # 设备映射必须固定为空:CI runner 的 C: 可能恰是 HarddiskVolume3,
        # 真实 QueryDosDevice 会把 NT 路径转换掉,透传断言就变成掷硬币
        with patch.object(etw, "query_device_map", lambda: {}):
            watcher._apply_event(etw.EVT_NAME_CREATE, 500, "\\Device\\HarddiskVolume3\\u\\a.dll", 0x1A, 0, 0, now)
            watcher._apply_event(etw.EVT_WRITE, 500, "", 0x1A, 0x2A, 4096, now + 0.1)

        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][0], 500)
        # 空映射下未知设备原样透传
        self.assertEqual(writes[0][1], "\\Device\\HarddiskVolume3\\u\\a.dll")

    def test_create_event_populates_object_map(self):
        watcher, writes, _ = self.make_watcher()

        watcher._apply_event(etw.EVT_CREATE, 500, "C:\\u\\b.exe", 0, 0x2B, 0, 1.0)
        # Write 事件 FileKey 未命中时回退 FileObject 关联
        watcher._apply_event(etw.EVT_WRITE, 500, "", 0x99, 0x2B, 100, 1.5)

        self.assertEqual(writes, [(500, "C:\\u\\b.exe")])

    def test_write_without_mapping_counts_unresolved(self):
        watcher, writes, _ = self.make_watcher()

        watcher._apply_event(etw.EVT_WRITE, 500, "", 0xEE, 0xEE, 1, 1.0)

        self.assertEqual(writes, [])
        self.assertEqual(watcher.stats["write_unresolved"], 1)

    def test_rename_updates_mapping_and_dispatches(self):
        watcher, writes, _ = self.make_watcher()

        watcher._apply_event(etw.EVT_CREATE, 500, "C:\\u\\tmp.exe", 0, 0x2C, 0, 1.0)
        watcher._apply_event(etw.EVT_RENAME_PATH, 500, "C:\\u\\final.exe", 0x33, 0x2C, 0, 2.0)
        watcher._apply_event(etw.EVT_WRITE, 500, "", 0x33, 0x2C, 1, 3.0)

        paths = [path for _, path in writes]
        self.assertIn("C:\\u\\final.exe", paths)
        # 改名后的写入按新路径解析,而不是旧路径
        self.assertNotIn("C:\\u\\tmp.exe", paths[1:])

    def test_delete_pops_mapping_and_fires_callback(self):
        watcher, writes, deletes = self.make_watcher()

        watcher._apply_event(etw.EVT_NAME_CREATE, 500, "C:\\u\\c.docx", 0x1D, 0, 0, 1.0)
        watcher._apply_event(etw.EVT_DELETE_PATH, 500, "C:\\u\\c.docx", 0x1D, 0x2D, 0, 2.0)
        watcher._apply_event(etw.EVT_WRITE, 500, "", 0x1D, 0, 1, 3.0)

        self.assertEqual(deletes, [(500, "C:\\u\\c.docx")])
        self.assertEqual(writes, [], "删除后关联表必须已弹出,后续写入不得再命中")

    def test_write_after_ttl_expiry_misses(self):
        watcher, writes, _ = self.make_watcher()

        watcher._apply_event(etw.EVT_NAME_CREATE, 500, "C:\\u\\old.dll", 0x1E, 0, 0, 1.0)
        watcher._apply_event(etw.EVT_WRITE, 500, "", 0x1E, 0, 1, 1.0 + etw.KEY_MAP_TTL_SECONDS + 1)

        self.assertEqual(writes, [])

    def test_lifecycle_state_machine(self):
        if not sys.platform == "win32":
            self.skipTest("仅 Windows")

        watcher = etw.EtwFileWatcher()

        self.assertEqual(watcher.state, "stopped")
        self.assertFalse(watcher.running)
        # 启动会话需要管理员 + 干净的系统状态,单测只验证状态不被误标
        self.assertIn(watcher.stop(), (True,))


class ConvertPropertyTests(unittest.TestCase):
    def test_unicode_string_stops_at_nul(self):
        raw = ctypes_buffer("C:\\a.dll\x00padding")

        self.assertEqual(etw.convert_property(etw.TDH_INTYPE_UNICODESTRING, raw, len(raw)), "C:\\a.dll")

    def test_numeric_little_endian(self):
        raw = (etw.ctypes.c_ubyte * 8)(0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

        self.assertEqual(etw.convert_property(etw.TDH_INTYPE_POINTER, raw, 8), 0x1A)


def ctypes_buffer(text):
    import ctypes

    encoded = text.encode("utf-16-le")
    return (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)


class UnknownProcessKeyTests(unittest.TestCase):
    """操作进程未识别的三态文案:ETW 在跑时不得再指向「内核驱动未启用」。"""

    def test_three_state_selection(self):
        from PYAS_Dialog import select_unknown_process_key

        self.assertEqual(select_unknown_process_key(True, False), "process_unknown")
        self.assertEqual(select_unknown_process_key(True, True), "process_unknown")
        self.assertEqual(select_unknown_process_key(False, True), "process_unknown_etw")
        self.assertEqual(select_unknown_process_key(False, False), "process_unknown_driver")

    def test_etw_key_localized_for_all_supported_langs(self):
        from PYAS_Dialog import DIALOG_TEXTS, SUPPORTED_LANGS, loc_dialog_text

        entry = DIALOG_TEXTS["process_unknown_etw"]

        for lang in SUPPORTED_LANGS:
            text = loc_dialog_text(lang, "process_unknown_etw")
            self.assertTrue(text, f"{lang} 缺 process_unknown_etw 词条")
            self.assertNotIn("Kernel", text, f"{lang} 的 ETW 文案不应再提内核驱动: {text}")


if __name__ == "__main__":
    unittest.main()
