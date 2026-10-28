from PYAS_Diagnostics import log_exception, report_log_path
import os
import sys
import time
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from PYAS_Engine import rule_scanner, pe_scanner, cloud_scanner
from PYAS_ETW import BurstHeuristic, IS_WINDOWS as ETW_WINDOWS
from PYAS_Behavior import (
    L2_SNAPSHOT_COOLDOWN_SECONDS, L2_THRESHOLD, L2_WINDOW_SECONDS, TouchedFilesLedger,
)
from PYAS_Version import VERSION


class RuntimeMixin:
    def init_environ(self):
        self.python = sys.executable

        if getattr(sys, "frozen", False):
            self.file_pyas = self.norm_path(sys.executable)
        else:
            self.file_pyas = self.norm_path(os.path.abspath(sys.argv[0]))

        self.args_pyas = sys.argv[1:]
        self.path_pyas = os.path.dirname(self.file_pyas)
        self.pid_pyas = int(os.getpid())

        self.path_appdata = os.environ.get("APPDATA")
        self.path_localappdata = os.environ.get("LOCALAPPDATA") or self.path_appdata
        self.path_name = os.environ.get("USERNAME")
        self.path_temp = os.environ.get(
            "TEMP", f"C:\\Users\\{self.path_name}\\AppData\\Local\\Temp"
        )
        self.path_config = os.environ.get("ALLUSERSPROFILE", "C:\\ProgramData")
        self.path_system = os.environ.get("SYSTEMROOT", "C:\\Windows")
        self.path_user = os.environ.get("USERPROFILE", f"C:\\Users\\{self.path_name}")

        self.path_systemp = os.path.join(self.path_system, "Temp")
        self.file_config = os.path.join(self.path_config, "PYAS", "Config.json")
        self.file_log = report_log_path()
        self.path_webview = os.path.join(
            self.path_localappdata or self.path_temp, "PYAS", "WebView2"
        )
        self.file_webview_log = self.file_log
        self.path_properties = os.path.join(self.path_pyas, "Engine", "Properties")
        self.path_heuristic = os.path.join(self.path_pyas, "Engine", "Heuristic")
        self.path_protect = os.path.join(self.path_pyas, "Plugins", "Filter")
        self.path_rules = os.path.join(self.path_pyas, "Plugins", "Rules")
        self.path_drivers = os.path.join(self.path_protect, "PYAS_Driver.sys")

    def init_variables(self):
        self.lock_workers = threading.RLock()
        self.feature_workers = {}
        self.feature_restarts = set()

        self.heuristic = rule_scanner()
        self.properties = pe_scanner()
        self.cloud = cloud_scanner()
        self.cloud_queue = queue.Queue()

        self.ui_queue = queue.Queue()
        self.start_daemon_thread(self.ui_dispatcher_thread)

        self.driver_port = None
        self.driver_stop_event = threading.Event()
        self.driver_listener_ready_event = threading.Event()
        self.driver_listener_failed_event = threading.Event()
        self.driver_listener_thread = None

        # 发起进程溯源 ETW 消费者(PYAS_ETW.EtwMixin 使用)
        self.lock_etw = threading.RLock()
        self.etw_watcher = None
        self.etw_started_at = None
        self._etw_pid_info = None
        self._etw_heuristic = BurstHeuristic() if ETW_WINDOWS else None
        self._etw_suffixes = frozenset()
        self._etw_suffix_stamp = 0.0

        # 行为防护(渐进监控 + 紧急卷影回滚,PYAS_Behavior.BehaviorMixin 使用)
        self._behavior_ledger = TouchedFilesLedger() if ETW_WINDOWS else None
        self._behavior_l2 = (
            BurstHeuristic(
                threshold=L2_THRESHOLD,
                window_seconds=L2_WINDOW_SECONDS,
                cooldown_seconds=L2_SNAPSHOT_COOLDOWN_SECONDS,
            )
            if ETW_WINDOWS
            else None
        )
        self._vss = None
        self._behavior_switch_value = False
        self._behavior_switch_stamp = 0.0
        self._behavior_auto_value = False
        self._behavior_auto_stamp = 0.0

        self.ui_ready_event = threading.Event()
        self.engine_initialized = False

        self.scan_running = False
        self.scan_preparing = False
        self.scan_stop_requested = False
        self.scan_finished = False

        self.virus_lock = {}
        self.virus_results = []

        self.scan_count = 0
        self.scan_events = {}
        self.hash_cache = {}
        self.file_scheduler = None

        self.mbr_backup = {}

        self.cloud_pending = set()
        self.cloud_cancel_event = threading.Event()

        self.autostart_mode = "unknown"

        self.last_io_counters = {}
        self.last_io_time = time.time()
        self.suspended_procs = set()

        self.lock_driver = threading.RLock()
        self.lock_driver_unload = threading.Lock()
        self.driver_unload_worker = None
        self.driver_unload_result = None
        self.closing = False

        self.lock_update = threading.RLock()
        self.lock_proc = threading.RLock()
        self.lock_net = threading.RLock()
        self.lock_io = threading.RLock()
        self.lock_interactive = threading.RLock()

        self.pyas_default = {
            "version": VERSION,
            "api_host": "https://pyas-security.com/",
            "api_key": "fBRZxYS1UxykM-qzNOlKOEl63WILzlvgNMn6QfsG6FXCAAIktCrOPTAfY5_hEyuZ",
            "suffix": [
                ".exe",
                ".dll",
                ".sys",
                ".ocx",
                ".scr",
                ".efi",
                ".acm",
                ".ax",
                ".cpl",
                ".drv",
                ".com",
                ".mui",
                ".pyd",
                ".wfx",
                ".api",
                ".awx",
                ".rll",
                ".winmd",
                ".bat",
                ".cmd",
                ".ps1",
                ".vbs",
                ".vbe",
                ".wsf",
                ".reg",
                ".html",
                ".js",
                ".jse",
                ".jsp",
                ".php",
                ".hta",
                ".lnk",
                ".py",
                ".sh",
                ".url",
                ".rtf",
                ".ini",
            ],
            "size": 256 * 1024 * 1024,
            "language": "english_switch",
            "theme": "system_switch",
            "first_launch": True,
            "process_switch": False,
            "suspend_switch": True,
            "load_switch": True,
            "document_switch": False,
            "system_switch": False,
            "driver_switch": False,
            # 驱动防护只影响「首页是否算作已受防护」的判断,不影响驱动本身;
            # 内核驱动装不上的机器不该永远挂着「防护未完全开启」,故默认开
            "driver_alert_exempt": True,
            # 首页连驱动灯一起隐藏(忽略驱动防护状态的二级选项),默认关:
            # 绝大多数机器看得见五盏灯更有说服力,只有确实不关心驱动的人才会关掉
            "driver_home_hidden": False,
            # 发起进程溯源:驱动事件(层 A)优先;ETW(层 B)由 PYAS_ETW
            # 实时消费 Kernel-File 事件,无需驱动,但要求管理员令牌。
            # 开关关闭时两层都不记录,弹窗退回系统占用查询。
            "etw_attribution_switch": True,
            # 行为防护:渐进监控 + 紧急卷影 + 回滚(数据源是 ETW,需管理员)。
            # 默认开 —— 随首次策略授权一次性启用;自动回滚保持默认关:
            # 恢复操作可能把合法批量写入打回旧版本,须显式开启
            "behavior_defense_switch": True,
            "behavior_auto_rollback": False,
            # 特权运行:开启时启动核对发现需提权防护未运行,自动恢复(一次
            # UAC)+提权重启;关闭则保持纠正且不打扰
            "elevated_run_switch": True,
            # 提权说明弹窗:提权前先说明,确认时默认勾选「以后自动申请」;
            # seen 记录是否确认过,auto=不再显示说明
            "elevation_prompt_seen": False,
            "elevation_prompt_auto": True,
            "network_switch": False,
            "extension_switch": False,
            "sensitive_switch": False,
            "cloud_switch": False,
            "suffix_switch": True,
            "autostart_switch": True,
            "context_switch": True,
            "interactive_switch": False,
            "interactive_timeout": 30,
            "notify_channel": "system",
            "interactive_auto_block": False,
            "classic_menu_switch": False,
            # 智能体加固:后台监控+事件审计的总开关(纯审计不拦截,默认开)
            "agent_switch": True,
            "ai_assist_switch": False,
            "ai_auto_execute": False,
            "ai_auto_execute_timeout": 60,
            # 延迟启动:先留出自主决策窗口再发起分析,期间零 token 消耗
            "ai_delay_switch": True,
            "ai_delay_seconds": 3,
            "ai_provider_mode": "local",
            "ai_base_url": "http://127.0.0.1:11434/v1",
            "ai_api_key": "",
            "ai_model": "",
            "ai_rule_drafts": [],
            "dnd_switch": False,
            "custom_rule": [],
            "white_list": [],
            "quarantine": [],
            "block_list": [],
            "suppress_rules": [],
        }

        self.pass_windows = [
            {"exe": "System Idle Process", "class": "", "title": ""},
            {"exe": "", "class": "Windows.UI.Core.CoreWindow", "title": ""},
            {"exe": "explorer.exe", "class": "", "title": ""},
        ]

        self.scan_pool = ThreadPoolExecutor(max_workers=2)
        self.protect_pool = ThreadPoolExecutor(max_workers=8)
        self.proc_pool = ThreadPoolExecutor(max_workers=16)
        self.start_daemon_thread(self.log_flush_thread)

        for _ in range(2):
            self.start_daemon_thread(self.cloud_worker)

        # 智能体持续监控:进 AI+ 页之外也能积累「检测到智能体」审计
        self.start_daemon_thread(self.agent_monitor_thread)

        # selftest.bat 的弹窗端到端自测:轮询数据目录的测试请求哨兵
        self.start_daemon_thread(self.selftest_threat_watchdog)

    def ui_dispatcher_thread(self):
        while not getattr(self, "closing", False):
            if getattr(self, "_window_interacting", False):
                time.sleep(0.05)
                continue
            batch = []

            try:
                batch.append(self.ui_queue.get(timeout=0.1))

                while len(batch) < 50:
                    try:
                        batch.append(self.ui_queue.get_nowait())
                    except queue.Empty:
                        break

                # 窗口可能在取批次的间隙被销毁(重启/退出竞态):对已释放的
                # WebView2 执行 evaluate_js 会抛 ObjectDisposedException,
                # pywebview 会把它当脚本错误记成 ERROR —— closing 时这批
                # JS 已无意义,直接丢弃且不按错误记
                if getattr(self, "closing", False) or self._window is None:
                    continue

                self.evaluate_js_safe("".join(batch))
            except queue.Empty:
                continue
            except Exception:
                if not getattr(self, "closing", False):
                    log_exception("PYAS_Runtime.RuntimeMixin.ui_dispatcher_thread:146")
                pass
            finally:
                for _ in batch:
                    self.ui_queue.task_done()

    def start_feature_thread(self, target, switch):
        with self.lock_workers:
            existing = self.feature_workers.get(switch)

            if existing and existing.is_alive():
                self.feature_restarts.add(switch)
                return existing

            def worker():
                try:
                    while True:
                        try:
                            target()
                        except Exception:
                            log_exception(f"RuntimeMixin.{target.__name__}")

                        with self.lock_config:
                            enabled = self.pyas_config.get(switch, False)

                        if not enabled or self.closing:
                            break

                        self.write_log(
                            "WARN",
                            "Protection Recovery",
                            detail=f"Restarting {switch}",
                            success=False,
                        )
                        time.sleep(0.5)
                finally:
                    with self.lock_workers:
                        if self.feature_workers.get(switch) is threading.current_thread():
                            self.feature_workers.pop(switch, None)

                        restart = switch in self.feature_restarts
                        self.feature_restarts.discard(switch)

                    with self.lock_config:
                        enabled = self.pyas_config.get(switch, False)

                    if restart and enabled and not self.closing:
                        self.start_feature_thread(target, switch)

            thread = threading.Thread(target=worker, daemon=True, name=f"PYAS.{target.__name__}")
            self.feature_workers[switch] = thread
            thread.start()
            return thread
