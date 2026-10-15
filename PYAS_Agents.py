# -*- coding: utf-8 -*-
"""智能体加固(P4 MVP):识别本机运行/已安装的 AI 编码代理,用于审计与告警上下文。

仅做用户态探测(进程枚举、快捷方式与安装位置存在性),不注入、不拦截、不扫盘;
检测到代理进程触发防护事件时,在决策审计里带上代理标记,让 AI 分析与人工裁决
都有上下文。界面按「已安装」过滤图标带。
"""
import ctypes
import glob
import os
import time

from PYAS_Diagnostics import log_exception

# 智能体目录:唯一真源(显示名/匹配 token/图标/徽标/安装位置线索)。
# 界面按「本机已安装」过滤后渲染图标带;activity 列表用 name 对齐。
# logo=None 表示没有方形图标,前端用 letter+color 渲染字母徽标。
# paths 为相对常见根目录(home / APPDATA / LOCALAPPDATA / Programs / npm)的 glob。
AGENT_CATALOG = (
    {"name": "AutoClaw",        "tokens": ("autoclaw",),
     "logo": "autoclaw.png",    "letter": "A",  "color": "#2563EB", "paths": ("autoclaw*",)},
    {"name": "ChatGPT",         "tokens": ("chatgpt", "codex"),
     "logo": "openai.svg",      "letter": "C",  "color": "#10A37F", "paths": (".codex", "codex*")},
    {"name": "Claude Code",     "tokens": ("claude",),
     "logo": "claude.svg",      "letter": "Cl", "color": "#D97757", "paths": (".claude", "claude*")},
    {"name": "DeepSeek",        "tokens": ("deepseek",),
     "logo": "deepseek.png",    "letter": "D",  "color": "#4D6BFE", "paths": ("deepseek*", ".deepseek*")},
    {"name": "豆包",             "tokens": ("doubao", "豆包"),
     "logo": "doubao.png",      "letter": "D",  "color": "#325AB4", "paths": ("doubao*", "豆包*")},
    {"name": "Hermes",          "tokens": ("hermes",),
     "logo": "hermes.png",      "letter": "H",  "color": "#8B5CF6", "paths": ("hermes*", ".hermes*")},
    {"name": "Kimi Code",       "tokens": ("kimi",),
     "logo": "kimi.png",        "letter": "K",  "color": "#1F2937", "paths": (".kimi*", "kimi*")},
    {"name": "MimoCode",        "tokens": ("mimocode", "mimo-code"),
     "logo": "mimo.png",        "letter": "M",  "color": "#FF6900", "paths": (".mimocode*", "mimo-code*")},
    {"name": "OpenClaw",        "tokens": ("openclaw",),
     "logo": "openclaw.svg",    "letter": "O",  "color": "#EF4444", "paths": ("openclaw*", ".openclaw*")},
    {"name": "千问",             "tokens": ("qwen", "qwen-code", "qianwen"),
     "logo": "qwen.png",        "letter": "Q",  "color": "#FF6A00", "paths": ("qwen*", ".qwen*")},
    {"name": "Trae",            "tokens": ("trae",),
     "logo": "trae.png",        "letter": "T",  "color": "#2563EB", "paths": ("Programs/*Trae*", "Trae CN", "TRAE SOLO CN")},
    {"name": "WorkBuddy",       "tokens": ("workbuddy",),
     "logo": "workbuddy.svg",   "letter": "W",  "color": "#12B7F5", "paths": ("WorkBuddy", ".workbuddy")},
    {"name": "ZCode",           "tokens": ("zcode",),
     "logo": "zcode.png",       "letter": "Z",  "color": "#2563EB", "paths": ("Programs/ZCode", ".zcode")},
    {"name": "Cursor",          "tokens": ("cursor",),
     "logo": "cursor.svg",      "letter": "Cu", "color": "#4A4A4A", "paths": ("Programs/cursor", "Cursor")},
    {"name": "GitHub Copilot",  "tokens": ("copilot",),
     "logo": "githubcopilot.svg", "letter": "G", "color": "#4A4A4A",
     "paths": (".vscode/extensions/github.copilot*", ".copilot")},
    {"name": "Cline",           "tokens": ("cline", "continue"),
     "logo": "cline.svg",       "letter": "Cl", "color": "#0EA5E9",
     "paths": (".vscode/extensions/cline.cline-*", ".continue")},
    {"name": "Aider",           "tokens": ("aider",),
     "logo": None,              "letter": "Ai", "color": "#0D9488",
     "paths": (".aider", "Python/Scripts/aider*")},
)

# 兼容旧引用:token 元组列表(名字/顺序随 AGENT_CATALOG)
AGENT_FINGERPRINTS = tuple((entry["name"], entry["tokens"]) for entry in AGENT_CATALOG)


def match_agent_name(exe_name):
    """可执行文件名 → 代理产品名;不匹配返回 None。"""
    name = str(exe_name or "").strip().casefold()

    if not name:
        return None

    for entry in AGENT_CATALOG:
        if any(token.casefold() in name for token in entry["tokens"]):
            return entry["name"]

    return None


def _process_is_elevated(pid):
    """查询进程令牌是否已提权(TokenElevation)。

    权限审计的最小实现:只读令牌属性,不改权限、不注入。
    查询失败一律按未提权处理——审计宁可少报,不可误报。
    """
    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32
    TOKEN_QUERY = 0x0008
    TOKEN_ELEVATION = 20

    for access in (0x1000, 0x0400):  # PROCESS_QUERY_LIMITED_INFORMATION, QUERY_INFORMATION
        handle = kernel32.OpenProcess(access, False, int(pid))

        if not handle:
            continue

        try:
            token = ctypes.c_void_p()

            if not advapi32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
                continue

            try:
                elevation = ctypes.c_ulong()
                returned = ctypes.c_ulong()

                if advapi32.GetTokenInformation(token, TOKEN_ELEVATION, ctypes.byref(elevation),
                        ctypes.sizeof(elevation), ctypes.byref(returned)):
                    return bool(elevation.value)
            finally:
                kernel32.CloseHandle(token)
        finally:
            kernel32.CloseHandle(handle)

    return False


def enumerate_process_names(lister=None):
    """返回 [(exe_name, pid), ...];非 Windows 或失败返回空列表。"""
    if lister is not None:
        return list(lister())

    if os.name != "nt":
        return []

    try:
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        TH32CS_SNAPPROCESS = 0x00000002

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if snapshot == ctypes.c_void_p(-1).value or not snapshot:
            return []

        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            found = []

            if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                while True:
                    found.append((entry.szExeFile, entry.th32ProcessID))

                    if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                        break

            return found
        finally:
            kernel32.CloseHandle(snapshot)
    except Exception:
        log_exception("PYAS_Agents.enumerate_process_names")
        return []


def _install_roots():
    """已安装检测的常见根目录(不扫盘,只做存在性探测)。"""
    env = os.environ
    home = os.path.expanduser("~")
    roots = [
        home,
        env.get("APPDATA") or "",
        env.get("LOCALAPPDATA") or "",
        os.path.join(env.get("LOCALAPPDATA") or "", "Programs"),
        os.path.join(env.get("APPDATA") or "", "npm"),
    ]
    return [root for root in roots if root]


def _probe_install_paths(entry):
    """L2:目录内 glob 命中任一即视为已安装(CLI 工具常用家目录/全局 bin)。"""
    patterns = entry.get("paths") or ()
    if not patterns:
        return False

    for root in _install_roots():
        for pattern in patterns:
            try:
                if glob.glob(os.path.join(root, pattern)):
                    return True
            except Exception:
                log_exception("PYAS_Agents._probe_install_paths")
    return False


def _scan_shortcut_names():
    """L2:开始菜单快捷方式文件名(小写、去扩展)。GUI 产品的通用安装信号。"""
    bases = [
        os.path.join(os.environ.get("APPDATA") or "",
                     "Microsoft", "Windows", "Start Menu", "Programs"),
        os.path.join(os.environ.get("ALLUSERSPROFILE", r"C:\ProgramData"),
                     "Microsoft", "Windows", "Start Menu", "Programs"),
    ]
    names = []
    for base in bases:
        if not os.path.isdir(base):
            continue
        for dirpath, _dirs, files in os.walk(base):
            for filename in files:
                if filename.lower().endswith(".lnk"):
                    names.append(os.path.splitext(filename)[0].casefold())
            if len(names) >= 800:
                return names
    return names


def _scan_npm_bin_names():
    """L2:npm 全局 bin 的文件名(小写、去扩展)。CLI 产品的通用安装信号。"""
    npm_dir = os.path.join(os.environ.get("APPDATA") or "", "npm")
    if not os.path.isdir(npm_dir):
        return []
    try:
        return [os.path.splitext(name)[0].casefold()
                for name in os.listdir(npm_dir)
                if os.path.isfile(os.path.join(npm_dir, name))]
    except OSError:
        log_exception("PYAS_Agents._scan_npm_bin_names")
        return []


class AgentMonitorMixin:
    # 同一产品的重复 sightings 最多 10 分钟记一条审计,防止刷日志
    SIGHTING_LOG_INTERVAL = 600

    def scan_agent_processes(self, lister=None):
        """枚举本机进程,返回命中的智能体活动(并写审计日志)。"""
        sightings = {}

        for exe_name, pid in enumerate_process_names(lister):
            product = match_agent_name(exe_name)

            if not product:
                continue

            item = sightings.setdefault(product, {"name": product, "pids": [],
                "exe": str(exe_name), "count": 0, "last_seen": time.time()})
            item["pids"].append(int(pid))
            item["count"] += 1
            item["last_seen"] = time.time()

        activity = sorted(sightings.values(), key=lambda item: item["name"])

        if getattr(self, "_agent_sightings", None) is None:
            self._agent_sightings = {}

        for item in activity:
            # 权限审计:逐进程查提权状态,0→>0 跳变才告警,稳态不重复刷
            elevated = 0

            for pid in item["pids"]:
                try:
                    elevated += 1 if _process_is_elevated(pid) else 0
                except Exception:
                    pass

            item["elevated"] = elevated
            known = self._agent_sightings.get(item["name"])
            last_logged = (known or {}).get("last_logged", 0)
            # 功能开关只关「监控+审计」:页面内浏览明细不受影响
            enabled = self._agent_feature_enabled()

            if (enabled and hasattr(self, "write_log")
                    and time.time() - last_logged >= self.SIGHTING_LOG_INTERVAL):
                self.write_log("INFO", "Agent Detected",
                    source=item["exe"],
                    detail=f"{item['name']} / {item['count']} process(es)")
                item["last_logged"] = time.time()

            if known:
                item["last_logged"] = max(known.get("last_logged", 0), item.get("last_logged", 0))

            was_elevated = (known or {}).get("elevated", 0)

            if (enabled and item["elevated"] > 0 and not was_elevated
                    and hasattr(self, "write_log")):
                self.write_log("WARN", "Agent Elevated",
                    source=item["exe"],
                    detail=(f"{item['name']}: {item['elevated']}/{item['count']} "
                            "process(es) with administrator token"))

        self._agent_sightings = {item["name"]: item for item in activity}
        return activity

    def get_agent_activity(self):
        return list(getattr(self, "_agent_sightings", {}).values())

    def _agent_feature_enabled(self):
        """智能体加固总开关(agent_switch):关=不监控、不写审计、不做事件标注。"""
        return bool(getattr(self, "pyas_config", {}).get("agent_switch", True))

    # 后台监控间隔:周期枚举进程,「检测到智能体」不再依赖用户进 AI+ 页
    MONITOR_INTERVAL = 300

    def agent_monitor_thread(self, interval=MONITOR_INTERVAL):
        """持续监控:周期扫描智能体进程,维护快照并落「检测到」审计。

        扫描本身毫秒级;审计受 SIGHTING_LOG_INTERVAL 限频,常驻不会刷日志。
        1 秒节拍同时承担关闭响应与开关跟随:关掉 agent_switch 后最多 1 秒
        停止扫描,重新打开后到下一个周期点自动恢复。
        """
        last_scan = 0.0

        while not getattr(self, "closing", False):
            if self._agent_feature_enabled() and time.monotonic() - last_scan >= interval:
                last_scan = time.monotonic()

                try:
                    self.scan_agent_processes()
                except Exception:
                    log_exception("PYAS_Agents.agent_monitor_thread")

            time.sleep(1)

    def list_installed_agents(self):
        """本机已安装的智能体(按 AGENT_CATALOG 顺序),供图标带过滤。

        分层信号:L1 正在运行的进程(最强)> L2 开始菜单快捷方式 /
        npm 全局 bin 的文件名匹配 > L2 安装位置 glob 存在性。
        只读探测,不扫盘、不启动任何进程。
        """
        origin = {}

        for exe_name, _pid in enumerate_process_names():
            name = match_agent_name(exe_name)

            if name and name not in origin:
                origin[name] = "process"

        try:
            shortcuts = _scan_shortcut_names()
        except Exception:
            log_exception("PYAS_Agents.list_installed_agents.shortcuts")
            shortcuts = []

        try:
            npm_bin = _scan_npm_bin_names()
        except Exception:
            log_exception("PYAS_Agents.list_installed_agents.npm")
            npm_bin = []

        for entry in AGENT_CATALOG:
            name = entry["name"]

            if name in origin:
                continue

            tokens = tuple(token.casefold() for token in entry["tokens"])

            if any(any(token in name_item for token in tokens) for name_item in shortcuts):
                origin[name] = "shortcut"
            elif any(any(token in name_item for token in tokens) for name_item in npm_bin):
                origin[name] = "npm"
            elif _probe_install_paths(entry):
                origin[name] = "path"

        return [
            {"name": entry["name"], "logo": entry["logo"], "letter": entry["letter"],
             "color": entry["color"], "via": origin[entry["name"]]}
            for entry in AGENT_CATALOG if entry["name"] in origin
        ]

    def note_agent_for_path(self, path):
        """防护事件来源命中智能体指纹时写一条审计(供 AI 分析与人工裁决参考)。

        开关关闭时返回 None:既不落审计,也不给弹窗/AI 做智能体标注。
        """
        product = match_agent_name(os.path.basename(str(path or "")))

        if not product or not self._agent_feature_enabled():
            return None

        if hasattr(self, "write_log"):
            self.write_log("INFO", "Agent Related Event", source=str(path), detail=product)

        return product
