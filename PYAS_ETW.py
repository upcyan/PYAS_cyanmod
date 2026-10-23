"""ETW 实时会话消费者:Microsoft-Windows-Kernel-File 追踪文件写入方。

为什么需要
----------
目录监听不携带发起方 PID;Restart Manager 只能看「此刻谁还开着文件」。
Kernel-File 提供程序在写入那一刻就给出 PID 与路径,覆盖「写完就关」的场景,
不需要内核驱动,代价是需要管理员令牌 + 常驻消费者。

订阅模型(Win10 1809+ manifest,结构稳定)
------------------------------------------
  10 NameCreate / 11 NameDelete : FileKey + FileName
  12 Create                     : FileObject + FileName
  16 Write                      : FileKey + FileObject + IOSize(不带路径)
  26 DeletePath                 : FileKey + FileObject + FilePath
  27 RenamePath / 28 SetLinkPath: FileKey + FileObject + FilePath(新路径)

Write 不带路径,先靠 10/12 建立「句柄键 → 路径」关联表,16 到达时反查;
27/28 直接带新路径。Read(15) 不订阅 —— 事件量低两个数量级。
关键字位(与 manifest 逐一核对):FILENAME 0x10 | CREATE 0x80 | WRITE 0x200
| DELETE_PATH 0x400 | RENAME_SETLINK_PATH 0x800 | CREATE_NEW_FILE 0x1000。

解析走 TDH(TdhGetPropertySize + TdhGetProperty),按属性名取值,
manifest 的版本差异(v0/v1 字段重排)由 TDH 消化,不硬编码偏移。

层级关系
--------
本模块与 PYAS_Attribution 配合:驱动事件(层 A)优先,ETW(层 B)其次,
Restart Manager 由 PYAS_Dialog 兜底。回调由 EtwMixin 注入,本模块自身
不 import 其他 PYAS 模块,可脱离主程序单独测试。

ABI 说明
--------
结构体布局与调用序列参照 pywintrace(FireEye,Apache-2.0),
字段顺序与 SDK 头文件(evntrace.h)逐一核对:EVENT_TRACE_LOGFILEW 的
LogFileName 在前、LoggerName 在后;不引入 pywintrace 运行时。

扩展
----
BurstHeuristic:同一进程短窗口内大量改写文档类文件 → 勒索行为启发,
命中后走托盘通知(只提醒不处置;自动处置需要策略层配合,见 behavior-defense.md)。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import os
import sys
import threading
import time
import uuid
from collections import OrderedDict

logger = logging.getLogger("PYAS.ETW")

IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------------------
# 常量与提供程序
# ---------------------------------------------------------------------------

KERNEL_FILE_PROVIDER = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
SESSION_NAME = "PYAS-Attribution-Trace"

# Kernel-File 关键字位(1903+ manifest;按需订阅,避开 Read 的洪流)
KW_FILENAME = 0x10
KW_CREATE = 0x80
KW_WRITE = 0x200
KW_DELETE_PATH = 0x400
KW_RENAME_SETLINK_PATH = 0x800
KW_CREATE_NEW_FILE = 0x1000
SUBSCRIBE_KEYWORDS = (
    KW_FILENAME | KW_CREATE | KW_WRITE | KW_DELETE_PATH | KW_RENAME_SETLINK_PATH | KW_CREATE_NEW_FILE
)

# 事件 ID(task value,与 manifest 核对)
EVT_NAME_CREATE = 10
EVT_NAME_DELETE = 11
EVT_CREATE = 12
EVT_WRITE = 16
EVT_DELETE_PATH = 26
EVT_RENAME_PATH = 27
EVT_SETLINK_PATH = 28
HANDLED_EVENT_IDS = frozenset(
    {EVT_NAME_CREATE, EVT_NAME_DELETE, EVT_CREATE, EVT_WRITE, EVT_DELETE_PATH, EVT_RENAME_PATH, EVT_SETLINK_PATH}
)

# 关联表 TTL 与容量:实测高写入率下(探针 30 秒 create=47768)4096 顶格,
# 条目未等到写入事件就被 FIFO 挤出 → 一半写入无法归因。提容 + 延长保留;
# TTL 同时防句柄指针复用错配(指针 120 秒内未被复用即过期)
KEY_MAP_TTL_SECONDS = 300.0
KEY_MAP_MAX_ENTRIES = 32768
PID_CACHE_TTL_SECONDS = 300.0
PID_CACHE_MAX_ENTRIES = 512
DEVICE_MAP_TTL_SECONDS = 300.0

# 会话缓冲:BufferSize 单位是 KB。过滤掉 Read 后事件率可控,给小缓冲降内存
SESSION_BUFFER_KB = 256
SESSION_MIN_BUFFERS = 8
SESSION_MAX_BUFFERS = 64

EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_CONTROL_STOP = 1
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
TRACE_LEVEL_VERBOSE = 5
ERROR_SUCCESS = 0
ERROR_INSUFFICIENT_BUFFER = 0x7A
ERROR_CANCELLED = 1223
MAX_UINT = 0xFFFFFFFF
INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF

TDH_INTYPE_UNICODESTRING = 1
TDH_INTYPE_UINT32 = 8
TDH_INTYPE_UINT64 = 10
TDH_INTYPE_POINTER = 16

# 关联表关心哪些属性名(TDH 按名解析,与模板版本无关)
WANTED_PROPERTIES = ("FileName", "FilePath", "FileKey", "FileObject", "IOSize")


def is_elevated() -> bool:
    """当前进程是否具备管理员令牌(订阅内核提供程序的硬前提)。"""
    if not IS_WINDOWS:
        return False

    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.IsUserAnAdmin.restype = ctypes.c_bool
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def available() -> tuple[bool, str]:
    """(是否可用, 原因码)。消费者已内置,只差管理员令牌。"""
    if not IS_WINDOWS:
        return (False, "unsupported-platform")

    if not is_elevated():
        return (False, "elevated-required")

    return (True, "ok")


# ---------------------------------------------------------------------------
# ctypes ABI(布局核对自 Windows SDK evntrace.h;参照 pywintrace,Apache-2.0)
# ---------------------------------------------------------------------------


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def guid_from_text(text: str) -> GUID:
    value = uuid.UUID(text)
    raw = value.bytes_le  # bytes_le 与 Windows GUID 内存布局一致
    return GUID(
        int.from_bytes(raw[0:4], "little"),
        int.from_bytes(raw[4:6], "little"),
        int.from_bytes(raw[6:8], "little"),
        (ctypes.c_ubyte * 8)(*raw[8:]),
    )


def guid_matches(struct_guid: GUID, text: str) -> bool:
    return bytes(struct_guid) == uuid.UUID(text).bytes_le


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [
        ("BufferSize", ctypes.c_ulong),
        ("ProviderId", ctypes.c_ulong),
        ("HistoricalContext", ctypes.c_ulonglong),
        ("TimeStamp", wt.LARGE_INTEGER),
        ("Guid", GUID),
        ("ClientContext", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
    ]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", ctypes.c_ulong),
        ("MinimumBuffers", ctypes.c_ulong),
        ("MaximumBuffers", ctypes.c_ulong),
        ("MaximumFileSize", ctypes.c_ulong),
        ("LogFileMode", ctypes.c_ulong),
        ("FlushTimer", ctypes.c_ulong),
        ("EnableFlags", ctypes.c_ulong),
        ("AgeLimit", ctypes.c_long),
        ("NumberOfBuffers", ctypes.c_ulong),
        ("FreeBuffers", ctypes.c_ulong),
        ("EventsLost", ctypes.c_ulong),
        ("BuffersWritten", ctypes.c_ulong),
        ("LogBuffersLost", ctypes.c_ulong),
        ("RealTimeBuffersLost", ctypes.c_ulong),
        ("LoggerThreadId", wt.HANDLE),
        ("LogFileNameOffset", ctypes.c_ulong),
        ("LoggerNameOffset", ctypes.c_ulong),
    ]


class EVENT_TRACE_HEADER_CLASS(ctypes.Structure):
    _fields_ = [("Type", ctypes.c_ubyte), ("Level", ctypes.c_ubyte), ("Version", ctypes.c_uint16)]


class EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_ushort),
        ("HeaderType", ctypes.c_ubyte),
        ("MarkerFlags", ctypes.c_ubyte),
        ("Class", EVENT_TRACE_HEADER_CLASS),
        ("ThreadId", ctypes.c_ulong),
        ("ProcessId", ctypes.c_ulong),
        ("TimeStamp", wt.LARGE_INTEGER),
        ("Guid", GUID),
        ("ClientContext", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
    ]


class EVENT_TRACE(ctypes.Structure):
    _fields_ = [
        ("Header", EVENT_TRACE_HEADER),
        ("InstanceId", ctypes.c_ulong),
        ("ParentInstanceId", ctypes.c_ulong),
        ("ParentGuid", GUID),
        ("MofData", ctypes.c_void_p),
        ("MofLength", ctypes.c_ulong),
        ("ClientContext", ctypes.c_ulong),
    ]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Bias", ctypes.c_long),
        ("StandardName", ctypes.c_wchar * 32),
        ("StandardDate", ctypes.c_ushort * 8),
        ("StandardBias", ctypes.c_long),
        ("DaylightName", ctypes.c_wchar * 32),
        ("DaylightDate", ctypes.c_ushort * 8),
        ("DaylightBias", ctypes.c_long),
    ]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    # 与 SDK 的 EVENT_TRACE_LOGFILE_HEADER64 对齐(见 pywintrace 同名结构):
    # c_wchar_p 在 x64 上就是指针宽度,与 64 位头部内嵌的指针字段一致
    _fields_ = [
        ("BufferSize", ctypes.c_ulong),
        ("MajorVersion", ctypes.c_ubyte),
        ("MinorVersion", ctypes.c_ubyte),
        ("SubVersion", ctypes.c_ubyte),
        ("SubMinorVersion", ctypes.c_ubyte),
        ("ProviderVersion", ctypes.c_ulong),
        ("NumberOfProcessors", ctypes.c_ulong),
        ("EndTime", wt.LARGE_INTEGER),
        ("TimerResolution", ctypes.c_ulong),
        ("MaximumFileSize", ctypes.c_ulong),
        ("LogFileMode", ctypes.c_ulong),
        ("BuffersWritten", ctypes.c_ulong),
        ("StartBuffers", ctypes.c_ulong),
        ("PointerSize", ctypes.c_ulong),
        ("EventsLost", ctypes.c_ulong),
        ("CpuSpeedInMHz", ctypes.c_ulong),
        ("LoggerName", ctypes.c_wchar_p),
        ("LogFileName", ctypes.c_wchar_p),
        ("TimeZone", TIME_ZONE_INFORMATION),
        ("BootTime", wt.LARGE_INTEGER),
        ("PerfFreq", wt.LARGE_INTEGER),
        ("StartTime", wt.LARGE_INTEGER),
        ("ReservedFlags", ctypes.c_ulong),
        ("BuffersLost", ctypes.c_ulong),
    ]


EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.c_void_p)
EVENT_TRACE_BUFFER_CALLBACK = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)


class EVENT_TRACE_LOGFILE(ctypes.Structure):
    # 字段顺序 = SDK 原文:LogFileName 在前,LoggerName 在后;
    # ProcessTraceMode 与 LogFileMode 是同一位置的 union,共享 4 字节
    _fields_ = [
        ("LogFileName", ctypes.c_wchar_p),
        ("LoggerName", ctypes.c_wchar_p),
        ("CurrentTime", ctypes.c_longlong),
        ("BuffersRead", ctypes.c_ulong),
        ("ProcessTraceMode", ctypes.c_ulong),
        ("CurrentEvent", EVENT_TRACE),
        ("LogfileHeader", TRACE_LOGFILE_HEADER),
        ("BufferCallback", EVENT_TRACE_BUFFER_CALLBACK),
        ("BufferSize", ctypes.c_ulong),
        ("Filled", ctypes.c_ulong),
        ("EventsLost", ctypes.c_ulong),
        ("EventRecordCallback", EVENT_RECORD_CALLBACK),
        ("IsKernelTrace", ctypes.c_ulong),
        ("Context", ctypes.c_void_p),
    ]


class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("Id", ctypes.c_ushort),
        ("Version", ctypes.c_ubyte),
        ("Channel", ctypes.c_ubyte),
        ("Level", ctypes.c_ubyte),
        ("Opcode", ctypes.c_ubyte),
        ("Task", ctypes.c_ushort),
        ("Keyword", ctypes.c_ulonglong),
    ]


class EVENT_HEADER(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_ushort),
        ("HeaderType", ctypes.c_ushort),
        ("Flags", ctypes.c_ushort),
        ("EventProperty", ctypes.c_ushort),
        ("ThreadId", ctypes.c_ulong),
        ("ProcessId", ctypes.c_ulong),
        ("TimeStamp", wt.LARGE_INTEGER),
        ("ProviderId", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("KernelTime", ctypes.c_ulong),
        ("UserTime", ctypes.c_ulong),
        ("ActivityId", GUID),
    ]


class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ProcessorNumber", ctypes.c_ubyte),
        ("Alignment", ctypes.c_ubyte),
        ("LoggerId", ctypes.c_ushort),
    ]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("EventHeader", EVENT_HEADER),
        ("BufferContext", ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount", ctypes.c_ushort),
        ("UserDataLength", ctypes.c_ushort),
        ("ExtendedData", ctypes.c_void_p),
        ("UserData", ctypes.c_void_p),
        ("UserContext", ctypes.c_void_p),
    ]


class nonStructType(ctypes.Structure):
    _fields_ = [
        ("InType", ctypes.c_ushort),
        ("OutType", ctypes.c_ushort),
        ("MapNameOffset", ctypes.c_ulong),
    ]


class EVENT_PROPERTY_INFO(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.c_ulong),
        ("NameOffset", ctypes.c_ulong),
        ("nonStructType", nonStructType),
        ("count", ctypes.c_ushort),
        ("length", ctypes.c_ushort),
        ("Reserved", ctypes.c_ulong),
    ]


class TRACE_EVENT_INFO(ctypes.Structure):
    _fields_ = [
        ("ProviderGuid", GUID),
        ("EventGuid", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("DecodingSource", ctypes.c_ulong),
        ("ProviderNameOffset", ctypes.c_ulong),
        ("LevelNameOffset", ctypes.c_ulong),
        ("ChannelNameOffset", ctypes.c_ulong),
        ("KeywordsNameOffset", ctypes.c_ulong),
        ("TaskNameOffset", ctypes.c_ulong),
        ("OpcodeNameOffset", ctypes.c_ulong),
        ("EventMessageOffset", ctypes.c_ulong),
        ("ProviderMessageOffset", ctypes.c_ulong),
        ("BinaryXMLOffset", ctypes.c_ulong),
        ("BinaryXMLSize", ctypes.c_ulong),
        ("ActivityIDNameOffset", ctypes.c_ulong),
        ("RelatedActivityIDNameOffset", ctypes.c_ulong),
        ("PropertyCount", ctypes.c_ulong),
        ("TopLevelPropertyCount", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
        ("EventPropertyInfoArray", EVENT_PROPERTY_INFO * 0),
    ]


class PROPERTY_DATA_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("PropertyName", ctypes.c_ulonglong),
        ("ArrayIndex", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
    ]


if IS_WINDOWS:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    tdh_lib = ctypes.WinDLL("tdh", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _StartTraceW = advapi32.StartTraceW
    _StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_wchar_p, ctypes.POINTER(EVENT_TRACE_PROPERTIES)]
    _StartTraceW.restype = ctypes.c_ulong

    _ControlTraceW = advapi32.ControlTraceW
    _ControlTraceW.argtypes = [ctypes.c_ulonglong, ctypes.c_wchar_p, ctypes.POINTER(EVENT_TRACE_PROPERTIES), ctypes.c_ulong]
    _ControlTraceW.restype = ctypes.c_ulong

    _EnableTraceEx2 = advapi32.EnableTraceEx2
    _EnableTraceEx2.argtypes = [
        ctypes.c_ulonglong,
        ctypes.POINTER(GUID),
        ctypes.c_ulong,
        ctypes.c_ubyte,
        ctypes.c_ulonglong,
        ctypes.c_ulonglong,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    _EnableTraceEx2.restype = ctypes.c_ulong

    _OpenTraceW = advapi32.OpenTraceW
    _OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILE)]
    _OpenTraceW.restype = ctypes.c_ulonglong

    _ProcessTrace = advapi32.ProcessTrace
    _ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    _ProcessTrace.restype = ctypes.c_ulong

    _CloseTrace = advapi32.CloseTrace
    _CloseTrace.argtypes = [ctypes.c_ulonglong]
    _CloseTrace.restype = ctypes.c_ulong

    _TdhGetEventInformation = tdh_lib.TdhGetEventInformation
    _TdhGetEventInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.POINTER(TRACE_EVENT_INFO),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    _TdhGetEventInformation.restype = ctypes.c_ulong

    _TdhGetPropertySize = tdh_lib.TdhGetPropertySize
    _TdhGetPropertySize.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(PROPERTY_DATA_DESCRIPTOR),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    _TdhGetPropertySize.restype = ctypes.c_ulong

    _TdhGetProperty = tdh_lib.TdhGetProperty
    _TdhGetProperty.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(PROPERTY_DATA_DESCRIPTOR),
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ubyte),
    ]
    _TdhGetProperty.restype = ctypes.c_ulong

    _QueryDosDeviceW = kernel32.QueryDosDeviceW
    _QueryDosDeviceW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
    _QueryDosDeviceW.restype = ctypes.c_ulong


# ---------------------------------------------------------------------------
# NT 设备路径 → DOS 路径
# ---------------------------------------------------------------------------


def query_device_map() -> dict[str, str]:
    """盘符 → \\Device\\... 前缀映射(唯一一处 OS 调用,测试用假映射替换)。"""
    mapping: dict[str, str] = {}

    if not IS_WINDOWS:
        return mapping

    for code in range(65, 91):
        drive = f"{chr(code)}:"
        buf = ctypes.create_unicode_buffer(1024)

        if _QueryDosDeviceW(drive, buf, 1024) and buf.value:
            mapping[buf.value] = drive

    return mapping


def nt_to_dos(path: str, mapping: dict[str, str]) -> str:
    """\\Device\\HarddiskVolume3\\... → C:\\...;前缀按最长匹配。

    没有对应盘符的设备前缀原样返回 —— 这类路径与目录监听给出的 DOS
    路径做 normcase(normpath) 后不会相等,查询只是不命中,不会错配。
    """
    if not path.startswith("\\"):
        return path

    best_device, best_drive = "", ""

    for device, drive in mapping.items():
        if path.startswith(device) and len(device) > len(best_device):
            best_device, best_drive = device, drive

    if best_drive:
        return best_drive + path[len(best_device):]

    return path


# ---------------------------------------------------------------------------
# 勒索启发:单进程窗口内大量改写(纯逻辑,可单测)
# ---------------------------------------------------------------------------

# 文档/媒体类后缀:勒索软件的主要目标;编译器写 .obj、浏览器写缓存都不在列。
# .db/.sqlite/.mdb/.accdb 特意排除:聊天/应用数据库被 QQ、微信等高频改写,
# 计入会把正常使用当成批量改写(实测 QQ.exe 10 秒 40 个 .db 触发误报)
BURST_TARGET_EXTENSIONS = frozenset(
    ".doc .docx .xls .xlsx .ppt .pptx .pdf .txt .md .csv .rtf "
    ".jpg .jpeg .png .gif .bmp .tif .tiff .webp .heic .psd "
    ".zip .rar .7z .tar .gz .odt .ods".split()
)
BURST_WINDOW_SECONDS = 10.0
BURST_THRESHOLD = 40
BURST_COOLDOWN_SECONDS = 60.0
BURST_MAX_TRACKED_PIDS = 8
BURST_SAMPLE_COUNT = 3


class BurstAlert:
    __slots__ = ("pid", "count", "samples")

    def __init__(self, pid: int, count: int, samples: list[str]) -> None:
        self.pid = pid
        self.count = count
        self.samples = samples


class BurstHeuristic:
    """按 PID 滑动窗口统计「不同目标文件」的改写数,超阈值即告警一次。

    按路径去重:加密器对同一文件反复写只算一次;编译器虽会写大量不同
    文件,但目标后缀已把 .obj/构建缓存挡在门外,不会误伤。
    """

    def __init__(
        self,
        window_seconds: float = BURST_WINDOW_SECONDS,
        threshold: int = BURST_THRESHOLD,
        cooldown_seconds: float = BURST_COOLDOWN_SECONDS,
        max_pids: int = BURST_MAX_TRACKED_PIDS,
    ) -> None:
        self._window = window_seconds
        self._threshold = threshold
        self._cooldown = cooldown_seconds
        self._max_pids = max_pids
        self._lock = threading.Lock()
        # pid -> (OrderedDict[路径 -> 时刻], 上次告警时刻)
        self._state: dict[int, tuple[OrderedDict, float]] = {}

    @staticmethod
    def is_target(path: str) -> bool:
        _, ext = os.path.splitext(path)
        return ext.lower() in BURST_TARGET_EXTENSIONS

    def record(self, pid: int, path: str, now: float | None = None) -> BurstAlert | None:
        if not self.is_target(path):
            return None

        stamp = time.monotonic() if now is None else now

        with self._lock:
            paths, last_alert = self._state.get(pid, (OrderedDict(), None))

            paths[path] = stamp
            paths.move_to_end(path)

            # 滑窗裁剪:时间到期即逐出
            horizon = stamp - self._window

            for key in list(paths.keys()):
                if paths[key] < horizon:
                    del paths[key]
                else:
                    break

            if len(paths) < self._threshold:
                self._state[pid] = (paths, last_alert)
                self._trim_locked()
                return None

            if last_alert is not None and stamp - last_alert < self._cooldown:
                self._state[pid] = (paths, last_alert)
                return None

            alert = BurstAlert(pid, len(paths), list(paths.keys())[:BURST_SAMPLE_COUNT])
            self._state[pid] = (paths, stamp)
            self._trim_locked()
            return alert

    def _trim_locked(self) -> None:
        # 冷进程的计数没有事件可清,容量到顶就淘汰最旧 pid
        # (当前 pid 刚被 move 到末尾,不会被自己挤掉)
        while len(self._state) > self._max_pids:
            self._state.pop(next(iter(self._state)), None)

    def forget(self, pid: int) -> None:
        with self._lock:
            self._state.pop(pid, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._state)


# ---------------------------------------------------------------------------
# 关联表与进程信息缓存
# ---------------------------------------------------------------------------


class PointerMap:
    """FileKey / FileObject 指针 → 路径。TTL + 容量上限,防指针复用错配。"""

    def __init__(self, ttl_seconds: float = KEY_MAP_TTL_SECONDS, max_entries: int = KEY_MAP_MAX_ENTRIES) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._lock = threading.Lock()
        self._entries: OrderedDict[int, tuple[str, float]] = OrderedDict()

    def set(self, pointer: int, path: str, now: float) -> None:
        if not pointer or not path:
            return

        with self._lock:
            self._entries[pointer] = (path, now)
            self._entries.move_to_end(pointer)

            while len(self._entries) > self._max:
                self._entries.popitem(last=False)

    def get(self, pointer: int, now: float) -> str | None:
        if not pointer:
            return None

        with self._lock:
            entry = self._entries.get(pointer)

            if not entry:
                return None

            path, stamp = entry

            if now - stamp > self._ttl:
                self._entries.pop(pointer, None)
                return None

            self._entries.move_to_end(pointer)
            return path

    def pop(self, pointer: int) -> None:
        if not pointer:
            return

        with self._lock:
            self._entries.pop(pointer, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class PidInfoCache:
    """pid → (进程名, 路径)。进程退出后 get_exe_info 就查不到了,
    必须在事件时刻解析;短命进程正是溯源最有价值的对象。"""

    def __init__(
        self,
        resolver=None,
        ttl_seconds: float = PID_CACHE_TTL_SECONDS,
        max_entries: int = PID_CACHE_MAX_ENTRIES,
    ) -> None:
        self._resolver = resolver
        self._ttl = ttl_seconds
        self._max = max_entries
        self._lock = threading.Lock()
        self._entries: OrderedDict[int, tuple[str, str, float]] = OrderedDict()

    def get(self, pid: int, now: float | None = None) -> tuple[str, str]:
        stamp = time.monotonic() if now is None else now

        with self._lock:
            entry = self._entries.get(pid)

            if entry:
                name, path, recorded = entry

                if stamp - recorded <= self._ttl:
                    self._entries.move_to_end(pid)
                    return (name, path)

                self._entries.pop(pid, None)

        resolved = ("", "")

        if self._resolver:
            try:
                answer = self._resolver(pid) or ("", "")
                resolved = (str(answer[0] or ""), str(answer[1] or ""))
            except Exception:
                logger.debug("pid resolver failed for %s", pid, exc_info=True)

        with self._lock:
            if resolved[0] or resolved[1]:
                self._entries[pid] = (resolved[0], resolved[1], stamp)
                self._entries.move_to_end(pid)

                while len(self._entries) > self._max:
                    self._entries.popitem(last=False)

        return resolved


# ---------------------------------------------------------------------------
# 会话控制 + 事件处理
# ---------------------------------------------------------------------------


class EtwFileWatcher:
    """Kernel-File 实时会话:订阅、TDH 解析、句柄关联、回调分发。

    生命周期:start() 幂等(已在跑直接成功);stop() 后可再次 start(),
    启动时会先清掉同名的遗留会话(崩溃残留会让 StartTrace 报已存在)。
    """

    def __init__(
        self,
        on_write=None,
        on_delete=None,
        resolve_pid=None,
        session_name: str = SESSION_NAME,
        provider_guid: str = KERNEL_FILE_PROVIDER,
    ) -> None:
        self._on_write = on_write or (lambda pid, path: None)
        self._on_delete = on_delete or (lambda pid, path: None)
        self._pid_info = PidInfoCache(resolve_pid)
        self._session_name = session_name
        self._provider_guid = provider_guid
        self._key_map = PointerMap()
        self._object_map = PointerMap()
        self._device_map: dict[str, str] = {}
        self._device_map_stamp = 0.0
        self._state_lock = threading.RLock()
        self._session_handle = 0
        self._trace_handle = 0
        self._consumer_thread: threading.Thread | None = None
        # 回调 thunk 必须挂在实例上,否则 WINFUNCTYPE 会被回收导致访问违例
        self._callback_thunk = EVENT_RECORD_CALLBACK(self._on_event)
        self._props = None
        self._props_buffer = None
        self._logfile = None
        # 状态:stopped / starting / running / error
        self.state = "stopped"
        self.last_error = ""
        self.stats = {
            "name_create": 0, "create": 0, "write": 0, "write_unresolved": 0,
            "rename": 0, "delete": 0, "other": 0, "parse_errors": 0,
        }

    # -- 公共接口 ----------------------------------------------------------

    @property
    def running(self) -> bool:
        return self.state == "running"

    def status(self) -> dict:
        with self._state_lock:
            return {
                "state": self.state,
                "last_error": self.last_error,
                "key_map": len(self._key_map),
                "object_map": len(self._object_map),
                "device_map": len(self._device_map),
                "stats": dict(self.stats),
            }

    def start(self) -> bool:
        with self._state_lock:
            if self.state in ("running", "starting"):
                return True

            self.state = "starting"
            self.last_error = ""

        try:
            self._cleanup_stale_session()
            self._start_session()
            self._start_consumer()
        except Exception as error:
            with self._state_lock:
                self.state = "error"
                self.last_error = str(error)

            logger.warning("ETW session start failed: %s", error, exc_info=True)
            return False

        with self._state_lock:
            self.state = "running"

        return True

    def stop(self) -> bool:
        with self._state_lock:
            if self.state == "stopped":
                return True

            self.state = "stopped"

        try:
            self._teardown_handles()
            return True
        except Exception as error:
            logger.warning("ETW session stop failed: %s", error, exc_info=True)
            return False

    # -- 会话生命周期 -------------------------------------------------------

    def _build_properties(self):
        name_chars = len(self._session_name) + 1
        buf_size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + name_chars * ctypes.sizeof(ctypes.c_wchar)
        buffer = ctypes.create_string_buffer(buf_size)
        props = ctypes.cast(buffer, ctypes.POINTER(EVENT_TRACE_PROPERTIES)).contents
        props.Wnode.BufferSize = buf_size
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        props.BufferSize = SESSION_BUFFER_KB
        props.MinimumBuffers = SESSION_MIN_BUFFERS
        props.MaximumBuffers = SESSION_MAX_BUFFERS
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        props.FlushTimer = 1
        props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        # 结构体与缓冲都挂在 self 上,StartTrace/ControlTrace 调用期间有效
        self._props_buffer = buffer
        self._props = props
        return props

    def _cleanup_stale_session(self):
        # 崩溃残留的同名会话会让 StartTrace 报 ERROR_ALREADY_EXISTS;
        # 先无条件停一次,会话不存在时这一步本身会报错,忽略即可
        self._build_properties()
        _ControlTraceW(0, self._session_name, self._props, EVENT_TRACE_CONTROL_STOP)

    def _start_session(self):
        self._build_properties()
        session_handle = ctypes.c_ulonglong(0)
        status = _StartTraceW(ctypes.byref(session_handle), self._session_name, self._props)

        if status != ERROR_SUCCESS:
            raise OSError(f"StartTraceW failed: {status}")

        self._session_handle = session_handle.value

        guid = guid_from_text(self._provider_guid)
        status = _EnableTraceEx2(
            session_handle.value,
            ctypes.byref(guid),
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            SUBSCRIBE_KEYWORDS,
            0,
            0,
            None,
        )

        if status != ERROR_SUCCESS:
            raise OSError(f"EnableTraceEx2 failed: {status}")

    def _start_consumer(self):
        logfile = EVENT_TRACE_LOGFILE()
        logfile.LoggerName = self._session_name
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        logfile.EventRecordCallback = self._callback_thunk
        self._logfile = logfile
        self._trace_handle = _OpenTraceW(ctypes.byref(logfile))

        if self._trace_handle in (0, INVALID_PROCESSTRACE_HANDLE):
            raise OSError(f"OpenTraceW failed: {ctypes.GetLastError()}")

        thread = threading.Thread(target=self._consume_loop, name="PYAS-ETW-Consumer", daemon=True)
        self._consumer_thread = thread
        thread.start()

    def _consume_loop(self):
        handle = ctypes.c_ulonglong(self._trace_handle)
        status = _ProcessTrace(ctypes.byref(handle), 1, None, None)

        # 主动停止路径:CloseTrace 让 ProcessTrace 以 ERROR_CANCELLED 返回
        if status not in (ERROR_SUCCESS, ERROR_CANCELLED):
            with self._state_lock:
                if self.state == "running":
                    self.state = "error"
                    self.last_error = f"ProcessTrace exited: {status}"

        logger.info("ETW consumer loop exited (status=%s)", status)

    def _teardown_handles(self):
        # 顺序:先 CloseTrace 让 ProcessTrace 返回,再停会话,再关会话句柄
        trace_handle = self._trace_handle

        if trace_handle:
            self._trace_handle = 0
            _CloseTrace(ctypes.c_ulonglong(trace_handle))

        thread = self._consumer_thread

        if thread and thread is not threading.current_thread():
            thread.join(timeout=3.0)

        session_handle = self._session_handle

        if session_handle:
            self._session_handle = 0
            guid = guid_from_text(self._provider_guid)
            _EnableTraceEx2(
                ctypes.c_ulonglong(session_handle),
                ctypes.byref(guid),
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                0,
                0,
                0,
                0,
                None,
            )
            self._build_properties()
            _ControlTraceW(
                ctypes.c_ulonglong(session_handle), self._session_name, self._props, EVENT_TRACE_CONTROL_STOP
            )
            _CloseTrace(ctypes.c_ulonglong(session_handle))

        self._consumer_thread = None
        self._logfile = None

    # -- 事件处理 -----------------------------------------------------------

    def _on_event(self, record_ptr):  # pragma: no cover - 真回调由 OS 调用
        try:
            record = ctypes.cast(record_ptr, ctypes.POINTER(EVENT_RECORD)).contents
            self._handle_record(record)
        except Exception:
            with self._state_lock:
                self.stats["parse_errors"] += 1

    def _handle_record(self, record):
        header = record.EventHeader

        if not guid_matches(header.ProviderId, self._provider_guid):
            return

        event_id = header.EventDescriptor.Id

        if event_id not in HANDLED_EVENT_IDS:
            with self._state_lock:
                self.stats["other"] += 1

            return

        properties = self._extract_properties(record)

        if properties is None:
            with self._state_lock:
                self.stats["parse_errors"] += 1

            return

        now = time.monotonic()
        file_key = properties.get("FileKey") or 0
        file_object = properties.get("FileObject") or 0

        if event_id == EVT_NAME_CREATE:
            self._apply_event(event_id, header.ProcessId, properties.get("FileName") or "", file_key, 0, 0, now)
        elif event_id == EVT_NAME_DELETE:
            self._key_map.pop(file_key)
        elif event_id == EVT_CREATE:
            self._apply_event(event_id, header.ProcessId, properties.get("FileName") or "", 0, file_object, 0, now)
        elif event_id == EVT_WRITE:
            self._apply_event(
                event_id, header.ProcessId, "", file_key, file_object, properties.get("IOSize") or 0, now
            )
        elif event_id in (EVT_RENAME_PATH, EVT_SETLINK_PATH):
            self._apply_event(
                event_id, header.ProcessId, properties.get("FilePath") or "", file_key, file_object, 0, now
            )
        elif event_id == EVT_DELETE_PATH:
            self._apply_event(
                event_id, header.ProcessId, properties.get("FilePath") or "", file_key, file_object, 0, now
            )

    def _apply_event(self, event_id, pid, path, file_key, file_object, io_size, now):
        """关联与分发核心:不碰 OS,输入全部显式传入(单测入口)。io_size 仅供调试。"""
        if event_id == EVT_NAME_CREATE:
            if path:
                self._key_map.set(file_key, path, now)

            with self._state_lock:
                self.stats["name_create"] += 1
            return

        if event_id == EVT_CREATE:
            if path:
                self._object_map.set(file_object, path, now)

            with self._state_lock:
                self.stats["create"] += 1
            return

        if event_id == EVT_WRITE:
            source = self._key_map.get(file_key, now) or self._object_map.get(file_object, now)

            with self._state_lock:
                self.stats["write" if source else "write_unresolved"] += 1

            if source:
                self._dispatch(pid, source, now)
            return

        if event_id in (EVT_RENAME_PATH, EVT_SETLINK_PATH):
            with self._state_lock:
                self.stats["rename"] += 1

            if path:
                # 改名 = 内容落在新路径上:关联表改指新路径并按写入分发
                self._key_map.set(file_key, path, now)
                self._object_map.set(file_object, path, now)
                self._dispatch(pid, path, now)
            return

        if event_id == EVT_DELETE_PATH:
            self._key_map.pop(file_key)
            self._object_map.pop(file_object)

            with self._state_lock:
                self.stats["delete"] += 1

            if path:
                self._notify_delete(pid, path, now)

    def _dispatch(self, pid: int, path: str, now: float) -> None:
        # pid 4 = System:ETW 在缓存回写时把写入算到 System 头上,并非真实
        # 写入者 —— 记进溯源与启发只会制造伪归属(实测触发「PID 4 勒索告警」)
        if pid <= 4:
            return

        dos_path = self._to_dos(path, now)

        if not dos_path:
            return

        try:
            self._on_write(pid, dos_path)
        except Exception:
            logger.debug("on_write callback failed", exc_info=True)

    def _notify_delete(self, pid: int, path: str, now: float) -> None:
        if pid <= 4:
            return

        dos_path = self._to_dos(path, now)

        if not dos_path:
            return

        try:
            self._on_delete(pid, dos_path)
        except Exception:
            logger.debug("on_delete callback failed", exc_info=True)

    def _to_dos(self, path: str, now: float) -> str:
        if not path.startswith("\\"):
            return path

        with self._state_lock:
            if now - self._device_map_stamp > DEVICE_MAP_TTL_SECONDS or not self._device_map:
                self._device_map = query_device_map()
                self._device_map_stamp = now

        return nt_to_dos(path, self._device_map)

    # -- TDH 属性解析 -------------------------------------------------------

    def _extract_properties(self, record) -> dict | None:
        """按属性名取值;返回 {名: int | str},schema 拿不到时返回 None。"""
        size = ctypes.c_ulong(0)
        status = _TdhGetEventInformation(ctypes.byref(record), 0, None, None, ctypes.byref(size))

        if status != ERROR_INSUFFICIENT_BUFFER or not size.value:
            return None

        buffer = ctypes.create_string_buffer(size.value)
        info = ctypes.cast(buffer, ctypes.POINTER(TRACE_EVENT_INFO))
        status = _TdhGetEventInformation(ctypes.byref(record), 0, None, info, ctypes.byref(size))

        if status != ERROR_SUCCESS:
            return None

        base = ctypes.cast(buffer, ctypes.c_void_p).value
        count = min(info.contents.TopLevelPropertyCount, info.contents.PropertyCount)
        array_base = ctypes.cast(info.contents.EventPropertyInfoArray, ctypes.c_void_p).value
        entry_size = ctypes.sizeof(EVENT_PROPERTY_INFO)
        wanted = set(WANTED_PROPERTIES)
        results: dict = {}

        for index in range(count):
            entry = EVENT_PROPERTY_INFO.from_address(array_base + index * entry_size)
            name = ctypes.wstring_at(base + entry.NameOffset)

            if name not in wanted:
                continue

            descriptor = PROPERTY_DATA_DESCRIPTOR()
            descriptor.PropertyName = base + entry.NameOffset
            descriptor.ArrayIndex = MAX_UINT
            prop_size = ctypes.c_ulong(0)

            if _TdhGetPropertySize(
                ctypes.byref(record), 0, None, 1, ctypes.byref(descriptor), ctypes.byref(prop_size)
            ) != ERROR_SUCCESS or not prop_size.value:
                continue

            out = ctypes.create_string_buffer(prop_size.value)
            status = _TdhGetProperty(
                ctypes.byref(record), 0, None, 1, ctypes.byref(descriptor),
                prop_size.value, ctypes.cast(out, ctypes.POINTER(ctypes.c_ubyte)),
            )

            if status != ERROR_SUCCESS:
                continue

            results[name] = convert_property(entry.nonStructType.InType, out, prop_size.value)

        return results


def convert_property(in_type: int, raw: ctypes.Array, size: int):
    """TDH 原始字节 → Python 值(字符串按 UTF-16 截到首个 NUL)。"""
    if in_type == TDH_INTYPE_UNICODESTRING:
        if size < 2:
            return ""

        return ctypes.wstring_at(raw, size // 2).split("\x00", 1)[0]

    return int.from_bytes(bytes(raw)[:size], "little")


# ---------------------------------------------------------------------------
# WindowAPI 集成(与 DriverMixin 同一套生命周期习惯)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 日志文案(写时本地化):detail 在 write_log 之前就按当前语言成形,
# 前端 translateLogDetail 查不到句式时原文就是用户语言 —— 与 PYAS_Agents
# 的 _AUDIT_TEXTS 同一模式。动作列("ETW Attribution"/"Ransomware Heuristic")
# 的翻译在 i18n.js,两者缺一不可,契约由 tests/test_log_action_i18n.py 强制。
# ---------------------------------------------------------------------------

# available() 原因码 → 文案键
UNAVAILABLE_REASON_KEYS = {
    "elevated-required": "unavailable_elevated",
    "unsupported-platform": "unavailable_platform",
}

ETW_LOG_TEXTS = {
    "unavailable_elevated": {
        "traditional_switch": "需要管理員權限，進程溯源未啟動",
        "simplified_switch": "需要管理员权限，进程溯源未启动",
        "english_switch": "Administrator rights required; attribution not started",
        "japanese_switch": "管理者権限が必要のため、プロセス追跡を開始できませんでした",
        "korean_switch": "관리자 권한이 필요하여 프로세스 추적을 시작하지 못했습니다",
        "french_switch": "Droits administrateur requis ; traçage non démarré",
        "spanish_switch": "Se requieren permisos de administrador; rastreo no iniciado",
        "hindi_switch": "व्यवस्थापक अधिकार आवश्यक; प्रक्रिया ट्रेसिंग प्रारंभ नहीं हुई",
        "arabic_switch": "يلزم صلاحيات المسؤول؛ لم يبدأ تتبع العمليات",
        "russian_switch": "Требуются права администратора; отслеживание не запущено",
        "slovenian_switch": "Zahtevane skrbniške pravice; sledenje ni zagnano",
    },
    "unavailable_platform": {
        "traditional_switch": "當前平台不支援",
        "simplified_switch": "当前平台不支持",
        "english_switch": "Not supported on this platform",
        "japanese_switch": "このプラットフォームでは対応していません",
        "korean_switch": "이 플랫폼은 지원되지 않습니다",
        "french_switch": "Non pris en charge sur cette plateforme",
        "spanish_switch": "No compatible con esta plataforma",
        "hindi_switch": "इस प्लेटफ़ॉर्म पर समर्थित नहीं",
        "arabic_switch": "غير مدعوم على هذه المنصة",
        "russian_switch": "Не поддерживается на этой платформе",
        "slovenian_switch": "Na tej platformi ni podprto",
    },
    "start_failed": {
        "traditional_switch": "啟動失敗： {0}",
        "simplified_switch": "启动失败： {0}",
        "english_switch": "Start failed: {0}",
        "japanese_switch": "開始に失敗しました: {0}",
        "korean_switch": "시작 실패: {0}",
        "french_switch": "Échec du démarrage : {0}",
        "spanish_switch": "Error al iniciar: {0}",
        "hindi_switch": "प्रारंभ विफल: {0}",
        "arabic_switch": "فشل البدء: {0}",
        "russian_switch": "Не удалось запустить: {0}",
        "slovenian_switch": "Zagon ni uspel: {0}",
    },
    "started": {
        "traditional_switch": "即時記錄檔案寫入方已開啟",
        "simplified_switch": "实时记录文件写入方已开启",
        "english_switch": "Real-time write attribution started",
        "japanese_switch": "ファイル書き込み元の記録を開始しました",
        "korean_switch": "파일 작성 프로세스 추적을 시작했습니다",
        "french_switch": "Traçage des écritures démarré",
        "spanish_switch": "Seguimiento de escrituras iniciado",
        "hindi_switch": "फ़ाइल लेखक ट्रैकिंग प्रारंभ",
        "arabic_switch": "بدأ تتبع كاتب الملفات",
        "russian_switch": "Отслеживание записывающих процессов запущено",
        "slovenian_switch": "Sledenje zapisovalcem datotek je zagnano",
    },
    "stopped": {
        "traditional_switch": "即時記錄檔案寫入方已停止",
        "simplified_switch": "实时记录文件写入方已停止",
        "english_switch": "Real-time write attribution stopped",
        "japanese_switch": "ファイル書き込み元の記録を停止しました",
        "korean_switch": "파일 작성 프로세스 추적을 중지했습니다",
        "french_switch": "Traçage des écritures arrêté",
        "spanish_switch": "Seguimiento de escrituras detenido",
        "hindi_switch": "फ़ाइल लेखक ट्रैकिंग बंद",
        "arabic_switch": "أُوقف تتبع كاتب الملفات",
        "russian_switch": "Отслеживание записывающих процессов остановлено",
        "slovenian_switch": "Sledenje zapisovalcem datotek je ustavljeno",
    },
    "stop_failed": {
        "traditional_switch": "停止失敗",
        "simplified_switch": "停止失败",
        "english_switch": "Stop failed",
        "japanese_switch": "停止に失敗しました",
        "korean_switch": "중지 실패",
        "french_switch": "Échec de l'arrêt",
        "spanish_switch": "Error al detener",
        "hindi_switch": "बंद करना विफल",
        "arabic_switch": "فشل الإيقاف",
        "russian_switch": "Не удалось остановить",
        "slovenian_switch": "Ustavitev ni uspela",
    },
    "engine_init_skipped": {
        "traditional_switch": "引擎初始化時未啟動，原因見上一條",
        "simplified_switch": "引擎初始化时未启动，原因见上一条",
        "english_switch": "Not started during engine init; see previous entry",
        "japanese_switch": "エンジン初期化時に開始できませんでした。前の項目を参照",
        "korean_switch": "엔진 초기화 중 시작하지 못했습니다. 이전 항목을 참조하세요",
        "french_switch": "Non démarré à l'init du moteur ; voir l'entrée précédente",
        "spanish_switch": "No iniciado durante la inicialización; ver la entrada anterior",
        "hindi_switch": "इंजन आरंभीकरण में प्रारंभ नहीं हुआ; पिछली प्रविष्टि देखें",
        "arabic_switch": "لم يبدأ أثناء تهيئة المحرك؛ راجع القيد السابق",
        "russian_switch": "Не запущено при инициализации движка; см. предыдущую запись",
        "slovenian_switch": "Ni zagnano pri inicializaciji mehanizma; glej prejšnji vnos",
    },
    "display_reconciled": {
        "traditional_switch": "需要管理員權限的防護未在運行，界面已按實際狀態顯示為關閉： {0}",
        "simplified_switch": "需要管理员权限的防护未在运行，界面已按实际状态显示为关闭： {0}",
        "english_switch": "Elevation-gated protection is not running; the interface now shows it as off: {0}",
        "japanese_switch": "管理者権限が必要な保護が実行されていないため、UI を実際の状態（オフ）に合わせました: {0}",
        "korean_switch": "관리자 권한이 필요한 보호가 실행 중이 아니어서 UI가 실제 상태(꺼짐)로 표시됩니다: {0}",
        "french_switch": "La protection soumise à élévation n'est pas active ; l'interface affiche désormais l'état réel (désactivé) : {0}",
        "spanish_switch": "La protección que requiere elevación no se está ejecutando; la interfaz ahora lo muestra como desactivado: {0}",
        "hindi_switch": "एलिवेशन-गेटेड सुरक्षा नहीं चल रही है; इंटरफ़ेस अब वास्तविक स्थिति (बंद) दिखाता है: {0}",
        "arabic_switch": "الحماية التي تتطلب الرفع ليست قيد التشغيل؛ تعرض الواجهة الحالة الفعلية (مغلق) الآن: {0}",
        "russian_switch": "Защита, требующая прав администратора, не запущена; интерфейс теперь показывает фактическое состояние (выкл): {0}",
        "slovenian_switch": "Zaščita, ki zahteva povišane pravice, ni aktivna; vmesnik zdaj prikazuje dejansko stanje (izklopljeno): {0}",
    },
    "reconcile_dialog_title": {
        "traditional_switch": "防護開關狀態核對",
        "simplified_switch": "防护开关状态核对",
        "english_switch": "Protection switch state check",
        "japanese_switch": "保護スイッチ状態の確認",
        "korean_switch": "보호 스위치 상태 확인",
        "french_switch": "Vérification des interrupteurs de protection",
        "spanish_switch": "Comprobación de interruptores de protección",
        "hindi_switch": "सुरक्षा स्विच स्थिति जांच",
        "arabic_switch": "التحقق من حالة مفاتيح الحماية",
        "russian_switch": "Проверка состояния переключателей защиты",
        "slovenian_switch": "Preverjanje stanja zaščitnih stikal",
    },
    "reconcile_item": {
        "traditional_switch": "{0}：設定為開啟，實際未在運行",
        "simplified_switch": "{0}：设定为开启，实际未在运行",
        "english_switch": "{0}: set to on, but not actually running",
        "japanese_switch": "{0}: オンに設定されていますが、実際には実行されていません",
        "korean_switch": "{0}: 켜짐으로 설정되었지만 실제로는 실행되지 않습니다",
        "french_switch": "{0} : activé, mais ne tourne pas réellement",
        "spanish_switch": "{0}: configurado como activado, pero no se está ejecutando",
        "hindi_switch": "{0}: चालू पर सेट है, लेकिन वास्तव में नहीं चल रहा है",
        "arabic_switch": "{0}: مضبوط على التشغيل لكنه لا يعمل فعليًا",
        "russian_switch": "{0}: установлено «вкл», но фактически не работает",
        "slovenian_switch": "{0}: nastavljeno na vklopljeno, dejansko pa ni v obratovanju",
    },
    "reconcile_question": {
        "traditional_switch": "是否恢復原有設定（開啟）？可能彈出管理員授權。選擇「否」將保持當前實際狀態。",
        "simplified_switch": "是否恢复原有设定（开启）？可能弹出管理员授权。选择「否」将保持当前实际状态。",
        "english_switch": "Restore the original setting (on)? An administrator prompt may appear. Choose No to keep the current actual state.",
        "japanese_switch": "元の設定（オン）を復元しますか？管理者承認が表示される場合があります。「いいえ」で現在の実際の状態を維持します。",
        "korean_switch": "원래 설정(켬)을 복원하시겠습니까? 관리자 승인이 나타날 수 있습니다. '아니요'를 선택하면 현재 실제 상태가 유지됩니다.",
        "french_switch": "Restaurer le réglage d'origine (activé) ? Une demande d'administrateur peut apparaître. Choisissez Non pour conserver l'état actuel.",
        "spanish_switch": "¿Restaurar la configuración original (activado)? Puede aparecer una solicitud de administrador. Elija No para mantener el estado actual.",
        "hindi_switch": "मूल सेटिंग (चालू) पुनर्स्थापित करें? व्यवस्थापक प्रॉम्प्ट दिखाई दे सकता है। वर्तमान वास्तविक स्थिति बनाए रखने के लिए 'नहीं' चुनें।",
        "arabic_switch": "هل تريد استعادة الإعداد الأصلي (تشغيل)؟ قد تظهر مطالبة المسؤول. اختر «لا» للإبقاء على الحالة الفعلية الحالية.",
        "russian_switch": "Восстановить исходную настройку (вкл)? Может появиться запрос администратора. «Нет» — сохранить текущее фактическое состояние.",
        "slovenian_switch": "Obnovim izvorno nastavitev (vklopljeno)? Prikaz se lahko zahteva skrbniško potrditev. Z »ne« ostane trenutno dejansko stanje.",
    },
    "switch_label_etw": {
        "traditional_switch": "進程溯源",
        "simplified_switch": "进程溯源",
        "english_switch": "Process attribution",
        "japanese_switch": "プロセス追跡",
        "korean_switch": "프로세스 추적",
        "french_switch": "Traçage de processus",
        "spanish_switch": "Rastreo de procesos",
        "hindi_switch": "प्रक्रिया ट्रेसिंग",
        "arabic_switch": "تتبع العمليات",
        "russian_switch": "Отслеживание процессов",
        "slovenian_switch": "Sledenje procesom",
    },
    "switch_label_behavior": {
        "traditional_switch": "行為防護",
        "simplified_switch": "行为防护",
        "english_switch": "Behavior defense",
        "japanese_switch": "ビヘイビア防御",
        "korean_switch": "행동 방어",
        "french_switch": "Défense comportementale",
        "spanish_switch": "Defensa conductual",
        "hindi_switch": "व्यवहार रक्षा",
        "arabic_switch": "الحماية السلوكية",
        "russian_switch": "Поведенческая защита",
        "slovenian_switch": "Vedenjska zaščita",
    },
    "burst_detail": {
        "traditional_switch": "{0} 在 {1} 秒內改寫了 {2} 個文件類檔案，疑似勒索行為",
        "simplified_switch": "{0} 在 {1} 秒内改写了 {2} 个文档类文件，疑似勒索行为",
        "english_switch": "{0} modified {2} documents within {1}s, possible ransomware",
        "japanese_switch": "{0} が {1} 秒間に {2} 件の文書ファイルを書き換えました（ランサムウェアの疑い）",
        "korean_switch": "{0}이(가) {1}초 내에 문서 {2}개를 변경했습니다(랜섬웨어 의심)",
        "french_switch": "{0} a modifié {2} documents en {1} s, rançongiciel possible",
        "spanish_switch": "{0} modificó {2} documentos en {1} s, posible ransomware",
        "hindi_switch": "{0} ने {1} सेकंड में {2} दस्तावेज़ बदले, रैंसमवेयर संभावित",
        "arabic_switch": "{0} عدّل {2} ملفًا خلال {1} ثانية، احتمال برمجيات فدية",
        "russian_switch": "{0} изменил(а) {2} документов за {1} с, возможно шифровальщик",
        "slovenian_switch": "{0} je v {1} s spremenil {2} dokumentov, mogoč izsiljevalski program",
    },
    "relaunch_toast_title": {
        "traditional_switch": "需要管理員權限",
        "simplified_switch": "需要管理员权限",
        "english_switch": "Administrator rights required",
        "japanese_switch": "管理者権限が必要です",
        "korean_switch": "관리자 권한이 필요합니다",
        "french_switch": "Droits administrateur requis",
        "spanish_switch": "Se requieren permisos de administrador",
        "hindi_switch": "व्यवस्थापक अधिकार आवश्यक",
        "arabic_switch": "يلزم صلاحيات المسؤول",
        "russian_switch": "Требуются права администратора",
        "slovenian_switch": "Zahtevane skrbniške pravice",
    },
    "relaunch_toast_body": {
        "traditional_switch": "設定已保存，PYAS 正在以管理員身份重啟；重啟後新開關立即生效，視窗會自動重新出現。",
        "simplified_switch": "设置已保存，PYAS 正在以管理员身份重启；重启后新开关立即生效，窗口会自动重新出现。",
        "english_switch": "Settings saved. PYAS is restarting with administrator rights; new switches take effect and the window reappears automatically.",
        "japanese_switch": "設定を保存しました。PYAS は管理者権限で再起動中です。再起動後、新しいスイッチが直ちに有効になり、ウィンドウは自動的に再表示されます。",
        "korean_switch": "설정이 저장되었습니다. PYAS가 관리자 권한으로 다시 시작 중입니다. 다시 시작 후 새 스위치가 즉시 적용되고 창이 자동으로 다시 나타납니다.",
        "french_switch": "Paramètres enregistrés. PYAS redémarre avec des droits administrateur ; les nouveaux interrupteurs prennent effet et la fenêtre réapparaît automatiquement.",
        "spanish_switch": "Configuración guardada. PYAS se está reiniciando con permisos de administrador; los nuevos interruptores surten efecto y la ventana reaparece automáticamente.",
        "hindi_switch": "सेटिंग्स सहेजी गईं। PYAS व्यवस्थापक अधिकारों के साथ पुनः प्रारंभ हो रहा है; नए स्विच प्रभावी होंगे और विंडो स्वतः दोबारा दिखाई देगी।",
        "arabic_switch": "تم حفظ الإعدادات. يُعاد تشغيل PYAS بصلاحيات المسؤول؛ تصبح المفاتيح الجديدة سارية وتظهر النافذة تلقائيًا من جديد.",
        "russian_switch": "Настройки сохранены. PYAS перезапускается с правами администратора; новые переключатели вступят в силу, окно появится автоматически.",
        "slovenian_switch": "Nastavitve so shranjene. PYAS se znova zagne s skrbniškimi pravicami; nova stikala takoj veljajo in se okno samodejno znova prikaže.",
    },
}


class EtwMixin:
    """etw_attribution_switch 的执行体:启动/停止消费者、溯源入缓存、
    勒索启发告警。依赖宿主提供 lock_etw/lock_config/pyas_config/
    write_log/_loc/dispatch_notification/get_exe_info —— RuntimeMixin
    的 __init__ 负责 etw_watcher/lock_etw/_etw_heuristic 等初值。"""

    @property
    def etw_running(self) -> bool:
        """供告警弹窗读取:ETW 层此刻是否在消费(只读,不加锁)。"""
        watcher = self.etw_watcher
        return bool(watcher and watcher.running)

    def _etw_log_text(self, key: str, *args: object) -> str:
        """按当前语言取日志文案;占位符按各语言语序填充。"""
        return self._loc(ETW_LOG_TEXTS[key]).format(*args)

    def _stop_etw_with_behavior_notice(self) -> bool:
        stopped = bool(self.stop_etw_consumer())

        # 行为防护的数据源是 ETW:源关了它就休眠,如实提醒
        with self.lock_config:
            behavior_on = bool(self.pyas_config.get("behavior_defense_switch", False))

        if stopped and behavior_on:
            from PYAS_Behavior import BEHAVIOR_LOG_TEXTS

            self.write_log(
                "WARN",
                "ETW Attribution",
                detail=self._loc(BEHAVIOR_LOG_TEXTS["etw_source_lost"]),
                success=False,
            )

        return stopped

    def reconcile_switch_display(self) -> None:
        """启动核对:开关期望值(策略文档)与实际生效状态不一致时,把运行时
        显示值纠正为实际,避免「显示开、实际没跑」。不回写策略文档 —— 那是
        管理员的意愿,下次提权启动仍会尝试生效。

        纠正后弹窗询问是否恢复原有设定(一次授权批量恢复);用户不响应则
        保持实际状态。弹窗在独立线程,不阻塞引擎初始化。
        """
        etw_running = bool(getattr(self, "etw_running", False))
        corrections = []

        with self.lock_config:
            for key, actual in (
                ("etw_attribution_switch", etw_running),
                (
                    "behavior_defense_switch",
                    etw_running and bool(self.pyas_config.get("behavior_defense_switch")),
                ),
            ):
                if bool(self.pyas_config.get(key)) and not actual:
                    self.pyas_config[key] = False
                    corrections.append(key)

        if not corrections:
            return

        self.write_log(
            "WARN",
            "ETW Attribution",
            detail=self._loc(ETW_LOG_TEXTS["display_reconciled"]).format(", ".join(corrections)),
            success=False,
        )
        # 界面的开关渲染自启动时缓存的配置,后端纠正不会自动反映 —— 显式推送
        # DOM 状态(与自启动失败回退同一套通道),否则开关仍显示「开」而实际没跑。
        # 注意不能派发 change:那会被当成一次需要授权的策略写
        for key in corrections:
            self.ui_queue.put(
                "(()=>{const el=document.querySelector('[data-config-key=" + key + "]');"
                "if(el)el.checked=false;})();"
            )
        # 特权运行开启:自动恢复(一次授权批量置回开启 + 提权重启),不再
        # 弹窗询问;关闭则按用户意愿保持关闭
        if bool(self.pyas_config.get("elevated_run_switch", True)):
            self.start_daemon_thread(lambda: self._auto_restore_for_privilege_run(corrections))

    def _auto_restore_for_privilege_run(self, keys: list[str]) -> None:
        self.restore_switches(keys)
        # 提权实例已就位:顺手把快捷方式打上提权标记,日常双击不再退回普通权限
        self._flag_user_shortcuts_elevated()

    def _flag_user_shortcuts_elevated(self) -> None:
        script = os.path.join(getattr(self, "path_pyas", ""), "Menu", "mark_shortcut_admin.ps1")

        if not os.path.isfile(script):
            return

        try:
            completed = subprocess.run(
                [
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", script, "-CommonLocations",
                    "-InstallDir", getattr(self, "path_pyas", ""),
                ],
                capture_output=True, timeout=120,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output = (completed.stdout or b"").decode("utf-8", "replace").strip()
        except Exception:
            logger.debug("shortcut flagging failed", exc_info=True)
            return

        if output:
            logging.getLogger("PYAS.Policy").info(
                "shortcut elevation flags: %s", output.replace("\n", "; ")
            )

    def _flag_shortcuts_if_pending(self) -> None:
        """提权实例启动后补打快捷方式提权标记(非提权实例的恢复/切换流程
        写入的待办标记);非提权实例无权限写公共位置,留给提权重启后。"""
        from PYAS_DataPaths import user_data_dir

        marker = os.path.join(user_data_dir(), "flag_shortcuts.pending")

        if not os.path.isfile(marker):
            return

        if not is_elevated():
            return

        self._flag_user_shortcuts_elevated()

        try:
            os.remove(marker)
        except OSError:
            pass

    def restore_switches(self, keys: list[str]) -> None:
        """一次授权批量恢复开关到开启:提交成功后,非提权走 helper 提权重启,
        提权环境直接拉起消费者。提交失败时调用方看到的值保持纠正态。"""
        scope = frozenset(keys)
        from PYAS_ETW import is_elevated

        def update():
            with self.lock_config:
                for key in keys:
                    self.pyas_config[key] = True

            return bool(self.save_config())

        result = self._policy_call(
            scope, update, False, 'restore:' + ','.join(sorted(keys)),
            relaunch_pid=os.getpid() if not is_elevated() else None,
        )

        if result and is_elevated():
            self.start_etw_consumer()

    def log_etw_stats_once(self, delays=(10.0, 30.0)) -> None:
        """启动后探测消费流量:溯源是否真的在工作,一条日志可验证。

        两个时点:10 秒看会话是否收到事件(create/write 应随系统写入增长),
        30 秒确认持续消费。parse_errors 恒为 0 才算解析链路健康。
        """

        def probe(delay_seconds: float):
            time.sleep(delay_seconds)

            with self.lock_etw:
                watcher = self.etw_watcher

            if not watcher:
                return

            stats = watcher.status()
            counts = stats.get("stats", {})
            detail = (
                "consumption probe @{0}s: create={create} write={write} "
                "write_unresolved={write_unresolved} rename={rename} delete={delete} "
                "other={other} parse_errors={parse_errors}; maps: key={key_map} "
                "object={object_map} devices={device_map}; state={state}"
            ).format(int(delay_seconds), key_map=stats.get("key_map", 0),
                     object_map=stats.get("object_map", 0),
                     device_map=stats.get("device_map", 0),
                     state=stats.get("state", "?"), **counts)
            self.write_log("INFO", "ETW Attribution", detail=detail)

        for delay in delays:
            self.start_daemon_thread(lambda d=delay: probe(d))

    def start_etw_consumer(self) -> bool:
        ok, reason = available()

        if not ok:
            # 未提权等场景:返回 False,update_config 会回拨开关并还原界面。
            # detail 写时本地化;未知原因码退回原样(不应发生,留诊断线索)
            detail = (
                self._etw_log_text(UNAVAILABLE_REASON_KEYS[reason])
                if reason in UNAVAILABLE_REASON_KEYS
                else f"Unavailable: {reason}"
            )
            self.write_log("WARN", "ETW Attribution", detail=detail, success=False)
            return False

        with self.lock_etw:
            watcher = self.etw_watcher

            if watcher and watcher.running:
                return True

            if watcher:
                watcher.stop()

            # pid 缓存归 mixin 所有:告警文案与溯源记录共用同一份「事件时刻」的进程名
            if getattr(self, "_etw_pid_info", None) is None:
                self._etw_pid_info = PidInfoCache(self._etw_resolve_pid)

            watcher = EtwFileWatcher(
                on_write=self._on_etw_write,
                on_delete=self._on_etw_delete,
                resolve_pid=self._etw_pid_info.get,
            )

            if not watcher.start():
                self.write_log(
                    "WARN",
                    "ETW Attribution",
                    detail=self._etw_log_text("start_failed", watcher.last_error),
                    success=False,
                )
                return False

            self.etw_watcher = watcher
            self.etw_started_at = time.time()

        self.write_log("INFO", "ETW Attribution", detail=self._etw_log_text("started"))
        return True

    def stop_etw_consumer(self) -> bool:
        with self.lock_etw:
            watcher = self.etw_watcher
            self.etw_watcher = None

        if watcher is None:
            return True

        stopped = watcher.stop()
        self.write_log(
            "INFO",
            "ETW Attribution",
            detail=self._etw_log_text("stopped" if stopped else "stop_failed"),
            success=stopped,
        )
        return stopped

    def get_etw_status(self) -> dict:
        with self.lock_etw:
            watcher = self.etw_watcher
            started_at = getattr(self, "etw_started_at", None)

        status = watcher.status() if watcher else {
            "state": "stopped", "last_error": "", "key_map": 0, "object_map": 0, "stats": {},
        }
        status["switch"] = bool(self.pyas_config.get("etw_attribution_switch", True))
        status["elevated"] = is_elevated()
        status["started_at"] = started_at
        return status

    def _etw_resolve_pid(self, pid: int):
        try:
            name, path = self.get_exe_info(pid) or (None, None)
            return (name or "", path or "")
        except Exception:
            return ("", "")

    def _etw_should_track(self, path: str) -> bool:
        """进缓存的后缀闸门:监控后缀 ∪ 勒索目标后缀,把系统写噪音挡掉。

        配置 5 秒才重读一次:每秒上千事件时不反复抢 config 锁。
        """
        now = time.monotonic()

        if now - self._etw_suffix_stamp > 5.0:
            with self.lock_config:
                suffixes = set(self.pyas_config.get("suffix", []) or [])

            suffixes.update(BURST_TARGET_EXTENSIONS)
            self._etw_suffixes = frozenset(ext.lower() for ext in suffixes)
            self._etw_suffix_stamp = now

        _, ext = os.path.splitext(path)
        return ext.lower() in self._etw_suffixes

    def _on_etw_write(self, pid: int, path: str) -> None:
        if not self._etw_should_track(path):
            return

        # 层 B:写入时刻记录发起方;名字此刻解析,进程退出后仍可归因
        try:
            from PYAS_Attribution import get_layer

            name, _ = self._etw_pid_info.get(pid)
            get_layer().record_etw(path, pid, name)
        except Exception:
            logger.debug("etw attribution record failed", exc_info=True)

        # 行为防护(L1 台账 + L2 升级快照;开关关闭时内部自判)。
        # 必须在勒索告警之前:告警若触发自动回滚,台账要已包含当前这条写入
        self._behavior_on_write(pid, path)

        burst = self._etw_heuristic.record(pid, path)

        if burst:
            self._etw_burst_alert(burst)

    def _on_etw_delete(self, pid: int, path: str) -> None:
        # 删除不进溯源缓存(文件已不在),但计入勒索启发:加密常伴随删除原文件
        if not self._etw_should_track(path):
            return

        # 行为防护:删除同样进台账,回滚时才能从快照找回被删文件(先于告警)
        self._behavior_on_write(pid, path)

        burst = self._etw_heuristic.record(pid, path)

        if burst:
            self._etw_burst_alert(burst)

    def _etw_burst_alert(self, burst: BurstAlert) -> None:
        name, _ = self._etw_pid_info.get(burst.pid)
        suspect = name or f"PID {burst.pid}"
        self.write_log(
            "WARN",
            "Ransomware Heuristic",
            detail=self._etw_log_text(
                "burst_detail", suspect, int(BURST_WINDOW_SECONDS), burst.count
            ),
            pid=burst.pid,
            source=suspect,
            success=False,
        )

        # L3:行为防护开启且 auto_rollback 时,这里顺带执行回滚
        if getattr(self, "_behavior_maybe_rollback", None):
            self._behavior_maybe_rollback(burst.pid)

        title = self._loc({
            "traditional_switch": "勒索行為警告",
            "simplified_switch": "勒索行为警告",
            "english_switch": "Ransomware warning",
            "japanese_switch": "ランサムウェア警告",
            "korean_switch": "랜섬웨어 경고",
            "french_switch": "Alerte rançongiciel",
            "spanish_switch": "Advertencia de ransomware",
            "hindi_switch": "रैंसमवेयर चेतावनी",
            "arabic_switch": "تحذير برمجيات الفدية",
            "russian_switch": "Предупреждение о шифровальщике",
            "slovenian_switch": "Opozorilo pred izsiljevalskim programom",
        })
        messages = {
            "traditional_switch": f"偵測到大量檔案改寫(疑似勒索行為): {suspect}",
            "simplified_switch": f"检测到大量文件改写(疑似勒索行为): {suspect}",
            "english_switch": f"Mass file modification detected (possible ransomware): {suspect}",
            "japanese_switch": f"大量のファイル書き換えを検出(ランサムウェアの疑い): {suspect}",
            "korean_switch": f"대량 파일 변경 감지(랜섬웨어 의심): {suspect}",
            "french_switch": f"Modification massive de fichiers détectée (rançongiciel possible) : {suspect}",
            "spanish_switch": f"Modificación masiva de archivos detectada (posible ransomware): {suspect}",
            "hindi_switch": f"बड़ी संख्या में फ़ाइल संशोधन पाया गया (रैंसमवेयर संभावित): {suspect}",
            "arabic_switch": f"تم اكتشاف تعديل ملفات واسع النطاق (احتمال برمجيات فدية): {suspect}",
            "russian_switch": f"Обнаружено массовое изменение файлов (возможно, шифровальщик): {suspect}",
            "slovenian_switch": f"Zaznana množična sprememba datotek (mogoč izsiljevalski program): {suspect}",
        }
        self.dispatch_notification(title, self._loc(messages))
