# -*- coding: utf-8 -*-
"""智能体加固(P4 MVP):识别本机运行的 AI 编码代理,用于审计与告警上下文。

仅做用户态进程枚举与指纹匹配,不注入、不拦截;检测到代理进程触发防护事件时,
在决策审计里带上代理标记,让 AI 分析与人工裁决都有上下文。
"""
import ctypes
import os
import time

from PYAS_Diagnostics import log_exception

# 主流 AI 编码代理的可执行名片段(大小写不敏感的包含匹配)
AGENT_FINGERPRINTS = (
    ("WorkBuddy", ("workbuddy",)),
    ("ZCode", ("zcode",)),
    ("AutoBot", ("autobot",)),
    ("ChatGPT", ("chatgpt", "codex")),
    ("Trae", ("trae",)),
    ("Kimi Code", ("kimi",)),
    ("MimoCode", ("mimocode", "mimo-code")),
    ("Claude Code", ("claude",)),
    ("Cursor", ("cursor",)),
    ("GitHub Copilot", ("copilot",)),
    ("Aider", ("aider",)),
    ("Cline", ("cline", "continue")),
)


def match_agent_name(exe_name):
    """可执行文件名 → 代理产品名;不匹配返回 None。"""
    name = str(exe_name or "").strip().casefold()

    if not name:
        return None

    for product, tokens in AGENT_FINGERPRINTS:
        if any(token in name for token in tokens):
            return product

    return None


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
            known = self._agent_sightings.get(item["name"])
            last_logged = (known or {}).get("last_logged", 0)

            if hasattr(self, "write_log") and time.time() - last_logged >= self.SIGHTING_LOG_INTERVAL:
                self.write_log("INFO", "Agent Detected",
                    source=item["exe"],
                    detail=f"{item['name']} / {item['count']} process(es)")
                item["last_logged"] = time.time()

            if known:
                item["last_logged"] = max(known.get("last_logged", 0), item.get("last_logged", 0))

        self._agent_sightings = {item["name"]: item for item in activity}
        return activity

    def get_agent_activity(self):
        return list(getattr(self, "_agent_sightings", {}).values())

    def note_agent_for_path(self, path):
        """防护事件来源命中智能体指纹时写一条审计(供 AI 分析与人工裁决参考)。"""
        product = match_agent_name(os.path.basename(str(path or "")))

        if product and hasattr(self, "write_log"):
            self.write_log("INFO", "Agent Related Event", source=str(path), detail=product)

        return product
