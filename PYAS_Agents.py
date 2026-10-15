# -*- coding: utf-8 -*-
"""智能体加固(P4 MVP):识别本机运行/已安装的 AI 编码代理,用于审计与告警上下文。

仅做用户态探测(进程枚举、快捷方式与安装位置存在性),不注入、不拦截、不扫盘;
检测到代理进程触发防护事件时,在决策审计里带上代理标记,让 AI 分析与人工裁决
都有上下文。界面按「已安装」过滤图标带。
"""
import ctypes
import glob
import os
import socket
import struct
import time

from PYAS_Diagnostics import log_exception
from PYAS_Signature import SignatureScanner

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

# 审计详情写入时就地取 UI 语言的模板(日志落盘后不会再翻译)。
# detected: {0}=产品名 {1}=进程数;elevated 两款: {0}=产品名 {1}=提权数 {2}=总进程数。
# elevated_first=首次扫到该产品即处于提权态(提权动作可能发生在很久以前);
# elevated_transition=上一轮扫过且当时无提权进程,本轮出现了→两次扫描间真提权了。
_AUDIT_TEXTS = {
    "traditional_switch": ("{0} / {1} 個處理程序執行中",
        "{0}：{1}/{2} 個處理程序取得管理員令牌（首次發現即提權）",
        "{0}：{1}/{2} 個處理程序取得管理員令牌（從未提權轉為提權）"),
    "simplified_switch": ("{0} / {1} 个进程运行中",
        "{0}：{1}/{2} 个进程拥有管理员令牌（首次发现即提权）",
        "{0}：{1}/{2} 个进程拥有管理员令牌（从未提权变为提权）"),
    "english_switch": ("{0} / {1} process(es) running",
        "{0}: {1}/{2} process(es) with an administrator token (first seen elevated)",
        "{0}: {1}/{2} process(es) elevated since the last scan"),
    "japanese_switch": ("{0} / {1} 個のプロセスが実行中",
        "{0}: {1}/{2} 個のプロセスが管理者トークンを取得（初回検出時に昇格済み）",
        "{0}: {1}/{2} 個のプロセスが管理者トークンを取得（前回スキャン後に昇格）"),
    "korean_switch": ("{0} / {1}개 프로세스 실행 중",
        "{0}: {1}/{2}개 프로세스가 관리자 토큰 보유(첫 발견 시 이미 상승)",
        "{0}: {1}/{2}개 프로세스가 관리자 토큰 보유(마지막 검사 이후 상승)"),
    "french_switch": ("{0} / {1} processus en cours",
        "{0} : {1}/{2} processus avec jeton administrateur (déjà élevé à la première détection)",
        "{0} : {1}/{2} processus élevés depuis la dernière analyse"),
    "spanish_switch": ("{0} / {1} proceso(s) en ejecución",
        "{0}: {1}/{2} proceso(s) con token de administrador (ya elevado al detectarse)",
        "{0}: {1}/{2} proceso(s) elevados desde el último análisis"),
    "hindi_switch": ("{0} / {1} प्रक्रियाएँ चल रही हैं",
        "{0}: {1}/{2} प्रक्रियाओं के पास व्यवस्थापक टोकन (पहली बार में ही विशेषाधिकार प्राप्त)",
        "{0}: {1}/{2} प्रक्रियाएँ अंतिम स्कैन के बाद विशेषाधिकार प्राप्त"),
    "arabic_switch": ("{0} / {1} عملية قيد التشغيل",
        "{0}: {1}/{2} عملية لها رمز مسؤول (مرتفعة منذ أول اكتشاف)",
        "{0}: {1}/{2} عملية ارتفعت صلاحياتها منذ الفحص السابق"),
    "russian_switch": ("{0} / {1} процес(ов) запущено",
        "{0}: {1}/{2} процесс(ов) с токеном администратора (уже повышены при первом обнаружении)",
        "{0}: {1}/{2} процесс(ов) повышены с последнего сканирования"),
    "slovenian_switch": ("{0} / {1} procesov teče",
        "{0}: {1}/{2} procesov ima skrbniški žeton (že povišano ob prvi zaznambi)",
        "{0}: {1}/{2} procesov povišanih od zadnjega pregleda"),
}


def match_agent_name(exe_name):
    """可执行文件名 → 代理产品名;不匹配返回 None。"""
    name = str(exe_name or "").strip().casefold()

    if not name:
        return None

    for entry in AGENT_CATALOG:
        if any(token.casefold() in name for token in entry["tokens"]):
            return entry["name"]

    return None


# 身份验证结果缓存:签名不随时间变化,同一文件一个进程周期只验一次
_verify_cache = {}
_signer = None


def _get_signer():
    """懒加载 WinVerifyTrust;初始化失败返回 None(调用方按未验证处理)。"""
    global _signer

    if _signer is None:
        try:
            scanner = SignatureScanner()
            scanner.init_windll(["wintrust"])
            _signer = scanner
        except Exception:
            log_exception("PYAS_Agents._get_signer")
            _signer = False

    return _signer or None


def _process_image_path(pid):
    """查询进程映像完整路径;失败返回空串。"""
    try:
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))
    except Exception:
        return ""

    if not handle:
        return ""

    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = ctypes.c_ulong(ctypes.sizeof(buf))

        if ctypes.windll.kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value

        return ""
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _query_tcp_rows():
    """枚举本机 TCP 连接(owner PID)。只读系统连接表,不拦截不改状态。

    返回 [(远端IP, 远端端口, PID)];表读取失败返回空列表。
    """
    try:
        iphlpapi = ctypes.windll.iphlpapi
        af_inet = 2
        tcp_table_owner_pid_all = 5
        size = ctypes.c_ulong(0)

        # 首次调用拿所需缓冲区大小(返回 122 = ERROR_INSUFFICIENT_BUFFER)
        iphlpapi.GetExtendedTcpTable(
            None, ctypes.byref(size), False, af_inet, tcp_table_owner_pid_all, 0)

        if not size.value:
            return []

        buf = ctypes.create_string_buffer(size.value)

        if iphlpapi.GetExtendedTcpTable(
                buf, ctypes.byref(size), False, af_inet, tcp_table_owner_pid_all, 0) != 0:
            return []

        count = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong)).contents.value
        rows = []
        base = ctypes.sizeof(ctypes.c_ulong)

        for i in range(min(count, 4096)):
            state, _la, _lp, ra, rp, pid = struct.unpack_from("<6I", buf, base + i * 24)

            if rp:
                rows.append((socket.inet_ntoa(struct.pack("<I", ra)), socket.ntohs(rp), pid))

        return rows
    except Exception:
        log_exception("PYAS_Agents._query_tcp_rows")
        return []


def _match_agent_connections(rows, pid_product):
    """纯函数:TCP 行里挑出属于智能体进程的远程端点,返回 [(产品名, 'ip:port')]。"""
    matched = []

    for remote_ip, remote_port, pid in rows:
        product = pid_product.get(int(pid))

        if product:
            matched.append((product, f"{remote_ip}:{remote_port}"))

    return matched


def verify_agent_identity(exe_path):
    """身份分档:Authenticode 有效签名=已验证;缺失/失败=未验证(名字级弱证据)。

    fail-closed:验证不出来就不给信用,任何异常都落未验证档。
    """
    path = str(exe_path or "")

    if not path or not os.path.isfile(path):
        return False

    key = os.path.normcase(os.path.abspath(path))

    if key in _verify_cache:
        return _verify_cache[key]

    signer = _get_signer()
    result = False

    if signer:
        try:
            result = bool(signer.sign_verify(path))
        except Exception:
            log_exception("PYAS_Agents.verify_agent_identity")
            result = False

    if len(_verify_cache) >= 64:
        _verify_cache.clear()

    _verify_cache[key] = result
    return result


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

        # 行为审计(网络):本轮 pid→产品映射,匹配系统 TCP 表提取智能体端点。
        # 只读连接表做快照,短命连接会漏采样——审计用途足够,不做拦截依据
        enabled = self._agent_feature_enabled()
        pid_product = {}

        for item in activity:
            for pid in item["pids"]:
                pid_product[int(pid)] = item["name"]

        conns_by_product = {}

        for product, endpoint in _match_agent_connections(_query_tcp_rows(), pid_product):
            conns_by_product.setdefault(product, []).append(endpoint)

        behavior = getattr(self, "_agent_behavior", None)
        if behavior is None:
            behavior = self._agent_behavior = {}
        seen_eps = getattr(self, "_agent_seen_endpoints", None)
        if seen_eps is None:
            seen_eps = self._agent_seen_endpoints = {}

        for item in activity:
            # 权限审计:逐进程查提权状态,0→>0 跳变才告警,稳态不重复刷
            elevated = 0

            for pid in item["pids"]:
                try:
                    elevated += 1 if _process_is_elevated(pid) else 0
                except Exception:
                    pass

            item["elevated"] = elevated

            # 身份分档:取一个代表进程的映像路径做签名验证(每产品每次扫描最多一次)
            image_path = ""

            for pid in item["pids"]:
                image_path = _process_image_path(pid)

                if image_path:
                    break

            try:
                item["verified"] = verify_agent_identity(image_path)
            except Exception:
                item["verified"] = False

            # 行为审计:连接快照(每产品最多 8 条)入明细,首见端点落网络审计
            conns = conns_by_product.get(item["name"], [])
            item["connections"] = [{"endpoint": endpoint} for endpoint in conns[:8]]
            behavior.setdefault(item["name"], {})["connections"] = item["connections"]

            known_eps = seen_eps.setdefault(item["name"], set())
            fresh = [endpoint for endpoint in conns if endpoint not in known_eps]

            if enabled and hasattr(self, "write_log"):
                for endpoint in fresh[:4]:  # 每轮最多记 4 条新端点,防端口翻动刷屏
                    self.write_log("INFO", "Agent Network",
                        source=item["exe"],
                        detail=f"{item['name']} → {endpoint}")

            if fresh:
                known_eps.update(fresh)

                if len(known_eps) > 128:  # 防膨胀:重置重学
                    seen_eps[item["name"]] = set(fresh)

            item["events"] = getattr(self, "_agent_event_counts", {}).get(item["name"], 0)

            known = self._agent_sightings.get(item["name"])
            last_logged = (known or {}).get("last_logged", 0)
            # 功能开关只关「监控+审计」:页面内浏览明细不受影响(enabled 已在循环外取)
            detected_text, elevated_first_text, elevated_transition_text = self._audit_texts()

            if (enabled and hasattr(self, "write_log")
                    and time.time() - last_logged >= self.SIGHTING_LOG_INTERVAL):
                self.write_log("INFO", "Agent Detected",
                    source=item["exe"],
                    detail=detected_text.format(item["name"], item["count"]))
                item["last_logged"] = time.time()

            if known:
                item["last_logged"] = max(known.get("last_logged", 0), item.get("last_logged", 0))

            was_elevated = (known or {}).get("elevated", 0)

            if (enabled and item["elevated"] > 0 and not was_elevated
                    and hasattr(self, "write_log")):
                # known 为 None=首次扫到即提权(提权动作可能发生在很久以前);
                # 有记录且此前无提权进程=两次扫描之间真的发生了提权。文案区分这两种情况
                text = elevated_first_text if known is None else elevated_transition_text
                # 不带 source:日志列表的明细列优先显示 source,文案要在第一眼看到
                self.write_log("WARN", "Agent Elevated",
                    detail=text.format(item["name"], item["elevated"], item["count"]))

        self._agent_sightings = {item["name"]: item for item in activity}
        return activity

    def get_agent_activity(self):
        activity = list(getattr(self, "_agent_sightings", {}).values())
        counts = getattr(self, "_agent_event_counts", {})

        for item in activity:
            item["events"] = counts.get(item["name"], 0)

        return activity

    def _agent_feature_enabled(self):
        """智能体加固总开关(agent_switch):关=不监控、不写审计、不做事件标注。"""
        return bool(getattr(self, "pyas_config", {}).get("agent_switch", True))

    def _audit_texts(self):
        """按当前 UI 语言取审计详情模板;未知语言回退英文。"""
        lang = getattr(self, "pyas_config", {}).get("language", "english_switch")
        return _AUDIT_TEXTS.get(lang, _AUDIT_TEXTS["english_switch"])

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

        counts = getattr(self, "_agent_event_counts", None)
        if counts is None:
            counts = self._agent_event_counts = {}
        counts[product] = counts.get(product, 0) + 1

        if hasattr(self, "write_log"):
            self.write_log("INFO", "Agent Related Event", source=str(path), detail=product)

        return product

    def identify_agent_for_event(self, source, process_path):
        """防护事件的智能体身份识别:名字命中落审计,签名验证定档。

        返回 (产品名或 None, 是否已验证);开关关闭一律 (None, False)。
        交互路径专用——自动拦截路径走 note_agent_for_path,不验签名省一次 IO。
        """
        if not self._agent_feature_enabled():
            return None, False

        for candidate in (source, process_path):
            if not candidate:
                continue

            product = match_agent_name(os.path.basename(str(candidate)))

            if not product:
                continue

            if hasattr(self, "write_log"):
                self.write_log("INFO", "Agent Related Event", source=str(candidate), detail=product)

            counts = getattr(self, "_agent_event_counts", None)
            if counts is None:
                counts = self._agent_event_counts = {}
            counts[product] = counts.get(product, 0) + 1

            try:
                return product, verify_agent_identity(candidate)
            except Exception:
                log_exception("PYAS_Agents.identify_agent_for_event")
                return product, False

        return None, False
