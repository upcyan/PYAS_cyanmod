# The fixed elevated helper must not initialize logging, engines or a WebView.
import sys as _policy_sys
if __name__ == '__main__' and len(_policy_sys.argv) == 2 and _policy_sys.argv[1] == '--pyas-bootstrap-probe':
    raise SystemExit(0)
if __name__ == '__main__' and len(_policy_sys.argv) > 1 and _policy_sys.argv[1] == '--pyas-policy-helper':
    from PYAS_PolicyWindows import helper_main as _policy_helper_main
    raise SystemExit(_policy_helper_main(_policy_sys.argv[2:]))

from PYAS_Diagnostics import log_exception, bind_report_logging
import os
import sys
import time
import copy
import json
import uuid
import queue
import platform
import threading
import logging
from PYAS_WindowIdentity import find_main_window
from PYAS_Encoding import decode_process_output
from PYAS_MenuState import MenuRegistrationState
from PYAS_Startup import (
    bootstrap_startup,
    check_webview_dependencies,
    prepare_webview_profile,
    restart_with_new_webview_profile,
    wait_for_recovery_parent,
)

STARTUP_LOG_PATH = bootstrap_startup() if __name__ == "__main__" else None
import msvcrt
import winreg
import pystray
import subprocess
import webview
import webbrowser
import ctypes
import ctypes.wintypes
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler
from PIL import Image
from socketserver import ThreadingTCPServer
from webview.dom import DOMEventHandler
from PYAS_Engine import sign_scanner, rule_scanner, pe_scanner, cloud_scanner
from PYAS_Dialog import MINMAXINFO, window_background_for
from PYAS_Protect import ProtectMixin
from PYAS_Scanner import ScannerMixin
from PYAS_Tools import (
    COPYDATASTRUCT,
    FILE_NOTIFY_INFORMATION,
    FILTER_MESSAGE_HEADER,
    IO_COUNTERS,
    LUID,
    LUID_AND_ATTRIBUTES,
    MEMORY_BASIC_INFORMATION,
    MIB_TCPROW_OWNER_PID,
    POINT,
    PROCESSENTRY32W,
    PROCESS_BASIC_INFORMATION,
    PYAS_FULL_MESSAGE,
    PYAS_MESSAGE,
    PYAS_USER_MESSAGE,
    RECT,
    SERVICE_STATUS_PROCESS,
    SHQUERYRBINFO,
    TOKEN_PRIVILEGES,
    ToolsMixin,
    UNICODE_STRING,
)


PYAS_WINDOW_TITLE = "PYAS Security Cyanmod"
WM_COPYDATA = 0x004A
SMTO_ABORTIFHUNG = 0x0002
SMTO_ERRORONEXIT = 0x0020
PYAS_SEND_MESSAGE_FLAGS = SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT
PYAS_MESSAGE_SCAN = 1
PYAS_MESSAGE_SHOW = 2
PYAS_MESSAGE_CLOSE = 3
PYAS_MESSAGE_QUIT = 4
PYAS_MESSAGE_DRIVER_UNLOAD = 5
PYAS_MESSAGE_DRIVER_UNINSTALL = 6
PYAS_MAINTENANCE_MESSAGE = 0x8000 + 0x501
PYAS_MAINTENANCE_COMMANDS = frozenset(
    {
        PYAS_MESSAGE_CLOSE,
        PYAS_MESSAGE_QUIT,
        PYAS_MESSAGE_DRIVER_UNLOAD,
        PYAS_MESSAGE_DRIVER_UNINSTALL,
    }
)

from PYAS_WinAPI import WindowsMixin
from PYAS_Config import ConfigMixin
from PYAS_PolicyAccess import PolicyAccessMixin
from PYAS_Logs import LogMixin
from PYAS_Runtime import RuntimeMixin
from PYAS_AI import AIMixin
from PYAS_Agents import AgentMonitorMixin


class _MainMixin(PolicyAccessMixin, WindowsMixin, ConfigMixin, LogMixin, RuntimeMixin, AIMixin, AgentMonitorMixin):
    def __init__(self):
        self._policy_required = True
        self._window = None
        self.tray_icon = None
        self.logs_data = []
        self.logs_dirty = False

        self.lock_config = threading.RLock()
        self.lock_logs = threading.RLock()
        self.lock_virus = threading.RLock()
        self.lock_file_ops = threading.RLock()
        self._window_interacting = False

        self.init_environ()
        self.init_windll()

        if not self.check_singleton("PYAS_Security_Mutex"):
            forwarded_exit_code = self.forward_to_existing_instance()

            if forwarded_exit_code is not None:
                os._exit(forwarded_exit_code)

            self.h_recovery_mutex = self.kernel32.CreateMutexW(
                None, False, "PYAS_Security_Recovery_Mutex"
            )

            if ctypes.get_last_error() == 183:
                os._exit(2)

        self.init_variables()
        self.load_config()
        self.load_logs()
        bind_report_logging(self)

    def find_existing_window(self, timeout=2.0):
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            hwnd = find_main_window(PYAS_WINDOW_TITLE)

            if hwnd:
                return hwnd

            time.sleep(0.05)

        return None

    def send_existing_window_message(self, hwnd, message_id, payload=None, timeout=1000):
        if not hwnd:
            return False

        if message_id in PYAS_MAINTENANCE_COMMANDS:
            try:
                return bool(
                    self.user32.SendMessageTimeoutW(
                        hwnd,
                        PYAS_MAINTENANCE_MESSAGE,
                        message_id,
                        None,
                        PYAS_SEND_MESSAGE_FLAGS,
                        timeout,
                        None,
                    )
                )
            except Exception:
                log_exception("MainMixin.send_maintenance_message")
                return False

        cds = COPYDATASTRUCT()
        cds.dwData = message_id
        buffer = None

        if payload is not None:
            encoded = str(payload).encode("utf-8")
            buffer = ctypes.create_string_buffer(encoded + b"\x00")
            cds.cbData = len(encoded) + 1
            cds.lpData = ctypes.cast(buffer, ctypes.c_void_p)
        else:
            cds.cbData = 0
            cds.lpData = None

        try:
            return bool(
                self.user32.SendMessageTimeoutW(
                    hwnd, WM_COPYDATA, 0, ctypes.byref(cds), PYAS_SEND_MESSAGE_FLAGS, timeout, None
                )
            )
        except Exception:
            log_exception("PYAS._MainMixin.send_existing_window_message:96")
            return False

    def _is_driver_service_absent(self):
        scm = self.advapi32.OpenSCManagerW(None, None, 0x0001)

        if not scm:
            return False

        service = None

        try:
            ctypes.set_last_error(0)
            service = self.advapi32.OpenServiceW(scm, "PYAS_Driver", 0x0004)

            if service:
                return False

            return ctypes.get_last_error() == 1060

        finally:
            if service:
                self.advapi32.CloseServiceHandle(service)

            self.advapi32.CloseServiceHandle(scm)

    def wait_for_existing_shutdown(self, timeout=30.0, require_service_removal=True):
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            window_closed = not find_main_window(PYAS_WINDOW_TITLE)
            service_removed = not require_service_removal or self._is_driver_service_absent()

            if window_closed and service_removed:
                return True

            time.sleep(0.1)

        return False

    def forward_to_existing_instance(self):
        maintenance_request = any(
            arg in self.args_pyas for arg in ("-quit", "-driver-uninstall", "-driver-unload")
        )
        hwnd = self.find_existing_window(timeout=10.0 if maintenance_request else 2.0)

        if not hwnd:
            return 2 if maintenance_request else None

        if "-quit" in self.args_pyas:
            if not self.send_existing_window_message(hwnd, PYAS_MESSAGE_QUIT, timeout=5000):
                return 2

            # 退出只要求主程序窗口关闭;驱动服务的删除由安装器的
            # FinalizeDriverRemoval 随后专门执行,这里等待服务删除只会超时失败。
            return 0 if self.wait_for_existing_shutdown(require_service_removal=False) else 2

        if "-driver-uninstall" in self.args_pyas:
            if not self.send_existing_window_message(
                hwnd, PYAS_MESSAGE_DRIVER_UNINSTALL, timeout=5000
            ):
                return 2

            return 0 if self.wait_for_existing_shutdown() else 2

        if "-driver-unload" in self.args_pyas:
            if not self.send_existing_window_message(
                hwnd, PYAS_MESSAGE_DRIVER_UNLOAD, timeout=5000
            ):
                return 2

            return 0 if self.wait_for_existing_shutdown(require_service_removal=False) else 2

        if "-scan" in self.args_pyas:
            try:
                idx = self.args_pyas.index("-scan")
                target = self.args_pyas[idx + 1]
            except Exception:
                log_exception("PYAS._MainMixin.forward_to_existing_instance:155")
                return 2

            if self.send_existing_window_message(hwnd, PYAS_MESSAGE_SCAN, target, timeout=1200):
                try:
                    self.user32.SetForegroundWindow(hwnd)
                except Exception:
                    log_exception("PYAS._MainMixin.forward_to_existing_instance:161")
                    pass

                return 0

            return 2

        if self.send_existing_window_message(hwnd, PYAS_MESSAGE_SHOW, timeout=1200):
            try:
                self.user32.SetForegroundWindow(hwnd)
            except Exception:
                log_exception("PYAS._MainMixin.forward_to_existing_instance:169")
                pass

            return 0

        return 2

    def check_singleton(self, name):
        try:
            self.h_mutex = self.kernel32.CreateMutexW(None, False, name)

            if ctypes.get_last_error() == 183:
                return False

            return True
        except Exception:
            log_exception("PYAS._MainMixin.check_singleton:181")
            return False

    def get_tray_text(self, key):
        texts = {
            "open_ui": {
                "traditional_switch": "開啟介面",
                "simplified_switch": "打开界面",
                "english_switch": "Open PYAS",
                "japanese_switch": "PYAS を開く",
                "korean_switch": "PYAS 열기",
                "french_switch": "Ouvrir PYAS",
                "spanish_switch": "Abrir PYAS",
                "hindi_switch": "PYAS खोलें",
                "arabic_switch": "فتح PYAS",
                "russian_switch": "Открыть PYAS",
                "slovenian_switch": "Odpri PYAS",
            },
            "optimize_mem": {
                "traditional_switch": "一鍵加速",
                "simplified_switch": "一键加速",
                "english_switch": "Memory Boost",
                "japanese_switch": "メモリ最適化",
                "korean_switch": "메모리 최적화",
                "french_switch": "Optimiser",
                "spanish_switch": "Optimizar",
                "hindi_switch": "मेमोरी बूस्ट",
                "arabic_switch": "تسريع",
                "russian_switch": "Ускорение",
                "slovenian_switch": "Optimizacija",
            },
            "check_update": {
                "traditional_switch": "檢查更新",
                "simplified_switch": "检查更新",
                "english_switch": "Check Update",
                "japanese_switch": "更新を確認",
                "korean_switch": "업데이트 확인",
                "french_switch": "Vérifier la mise à jour",
                "spanish_switch": "Buscar actualizaciones",
                "hindi_switch": "अद्यतन जाँचे",
                "arabic_switch": "التحقق من التحديثات",
                "russian_switch": "Проверить обновления",
                "slovenian_switch": "Preveri posodobitve",
            },
            "exit_app": {
                "traditional_switch": "退出防護",
                "simplified_switch": "退出防护",
                "english_switch": "Exit Security",
                "japanese_switch": "保護を終了",
                "korean_switch": "보호 종료",
                "french_switch": "Quitter la sécurité",
                "spanish_switch": "Salir de la seguridad",
                "hindi_switch": "सुरक्षा से बाहर निकलें",
                "arabic_switch": "خروج من الحماية",
                "russian_switch": "Выйти из защиты",
                "slovenian_switch": "Izhod iz zaščite",
            },
        }
        return self._loc(texts.get(key, {}))

    def get_app_icon(self):
        icon_path = os.path.join(self.path_pyas, "Interface", "static", "img", "icon.ico")

        if os.path.exists(icon_path):
            try:
                return Image.open(icon_path)
            except Exception:
                log_exception("PYAS._MainMixin.get_app_icon:218")
                pass

    def show_tray(self):
        if self.tray_icon is not None:
            return

        menu = pystray.Menu(
            pystray.MenuItem(
                lambda item: self.get_tray_text("open_ui"), self.toggle_window_activation, default=True
            ),
            pystray.MenuItem(lambda item: self.get_tray_text("optimize_mem"), self.optimize_memory),
            pystray.MenuItem(
                lambda item: self.get_tray_text("check_update"), self.tray_check_update
            ),
            pystray.MenuItem(lambda item: self.get_tray_text("exit_app"), self.close),
        )
        self.tray_icon = pystray.Icon("PYAS", self.get_app_icon(), "PYAS Security Cyanmod", menu)
        self.tray_icon.run_detached()
        self._start_foreground_watch()

    def tray_check_update(self, icon=None, item=None):
        def _check():
            res = self.check_update()

            title_error = self._loc(
                {
                    "traditional_switch": "錯誤",
                    "simplified_switch": "错误",
                    "english_switch": "Error",
                    "japanese_switch": "エラー",
                    "korean_switch": "오류",
                    "french_switch": "Erreur",
                    "spanish_switch": "Error",
                    "hindi_switch": "त्रुटि",
                    "arabic_switch": "خطأ",
                    "russian_switch": "Ошибка",
                    "slovenian_switch": "Napaka",
                }
            )

            title_prompt = self._loc(
                {
                    "traditional_switch": "提示",
                    "simplified_switch": "提示",
                    "english_switch": "Prompt",
                    "japanese_switch": "プロンプト",
                    "korean_switch": "프롬프트",
                    "french_switch": "Indication",
                    "spanish_switch": "Aviso",
                    "hindi_switch": "सुझाव",
                    "arabic_switch": "تلميح",
                    "russian_switch": "Подсказка",
                    "slovenian_switch": "Namig",
                }
            )

            msg_fail = self._loc(
                {
                    "traditional_switch": "檢查更新失敗",
                    "simplified_switch": "检查更新失败",
                    "english_switch": "Update check failed",
                    "japanese_switch": "アップデートの確認に失敗しました",
                    "korean_switch": "업데이트 확인 실패",
                    "french_switch": "Échec de la vérification des mises à jour",
                    "spanish_switch": "Fallo al buscar actualizaciones",
                    "hindi_switch": "अपडेट की जाँच विफल रही",
                    "arabic_switch": "فشل التحقق من التحديثات",
                    "russian_switch": "Ошибка проверки обновлений",
                    "slovenian_switch": "Preverjanje posodobitev ni uspelo",
                }
            )

            msg_new = self._loc(
                {
                    "traditional_switch": "發現新版本",
                    "simplified_switch": "发现新版本",
                    "english_switch": "New version found",
                    "japanese_switch": "新しいバージョンが見つかりました",
                    "korean_switch": "새 버전을 찾았습니다",
                    "french_switch": "Nouvelle version trouvée",
                    "spanish_switch": "Nueva versión encontrada",
                    "hindi_switch": "नया संस्करण मिला",
                    "arabic_switch": "تم العثور على إصدار جديد",
                    "russian_switch": "Найдена новая версия",
                    "slovenian_switch": "Najdena nova različica",
                }
            )

            msg_latest = self._loc(
                {
                    "traditional_switch": "當前已是最新版本",
                    "simplified_switch": "当前已是最新版本",
                    "english_switch": "Currently at latest version",
                    "japanese_switch": "現在は最新バージョンです",
                    "korean_switch": "현재 최신 버전입니다",
                    "french_switch": "Actuellement à la dernière version",
                    "spanish_switch": "Actualmente en la última versión",
                    "hindi_switch": "वर्तमान में नवीनतम संस्करण है",
                    "arabic_switch": "أنت تستخدم أحدث إصدار حاليًا",
                    "russian_switch": "Установлена последняя версия",
                    "slovenian_switch": "Trenutno imate najnovejšo različico",
                }
            )

            if res.get("error"):
                self.show_alert(title_error, msg_fail, "error")

            elif res.get("has_update"):
                msg = (
                    f"{msg_new} {res.get('latest')}\n({res.get('current')} -> {res.get('latest')})"
                )

                if self.show_confirm(title_prompt, msg):
                    self.open_url(res.get("url"))

            else:
                msg = f"{msg_latest} {res.get('current')}"
                self.show_alert(title_prompt, msg, "info")

        threading.Thread(target=_check, daemon=True).start()

    def _start_foreground_watch(self):
        """每 150ms 采一次前台窗口,只记本窗口是否在前台。

        托盘点击发生在 Explorer 抢走前台之后,现场问不出「点之前在前台吗」;
        采样线程把这个信息在点击前备好。GetForegroundWindow 只读一个整数,开销可忽略。"""
        if getattr(self, '_foreground_watch_started', False):
            return

        self._foreground_watch_started = True

        # HWND 在 64 位下是 8 字节指针,不声明 restype 会被 ctypes 当 c_int 截断,
        # 比较永远不相等 —— 采样就永远记不到「在前台」。
        user32 = ctypes.WinDLL('user32', use_last_error=True)
        user32.GetForegroundWindow.argtypes = []
        user32.GetForegroundWindow.restype = ctypes.c_void_p

        def loop():
            while not getattr(self, 'closing', False):
                try:
                    hwnd = self._find_main_hwnd()
                    foreground = user32.GetForegroundWindow()

                    if hwnd and foreground and int(foreground) == int(hwnd):
                        self._last_foreground_at = time.monotonic()
                except Exception:
                    log_exception('PYAS._foreground_watch')

                time.sleep(0.15)

        threading.Thread(target=loop, name='pyas-foreground-watch', daemon=True).start()

    def toggle_window_activation(self, icon=None, item=None):
        """托盘点击:窗口在前台才最小化,否则先置顶显示。

        这是资源管理器任务栏按钮的行为 —— 只按"可见/隐藏"判断会导致
        "窗口开着但被别的程序盖住,点托盘反而把它收起来"。"""
        hwnd = self._find_main_hwnd()

        if not hwnd:
            self.restore_from_tray(icon, item)
            return

        try:
            minimized = self.user32.IsIconic(ctypes.c_void_p(hwnd))
        except Exception:
            minimized = False

        # 用「最近一次处于前台」的时间判断,不用 GetForegroundWindow:
        # 点托盘那一刻前台已经转给 explorer,现场问必然答「不在前台」。
        # 也不能用 WM_ACTIVATE 时间戳 —— 用户常常是窗口在前面放了一会儿才去点托盘,
        # 距最后一次激活早超过阈值,表现就是永远只置顶。
        recently_foreground = (
            time.monotonic() - getattr(self, '_last_foreground_at', 0.0)
        ) < 0.5

        if not minimized and recently_foreground:
            self.minimize()
        else:
            self.bring_window_to_front(icon, item)

    def bring_window_to_front(self, icon=None, item=None):
        """托盘「打开主界面」:恢复并置顶,**绝不最小化**。

        之前这里挂的是"切换"逻辑(可见就最小化),导致窗口开着时点菜单反而把它收起来。
        """
        self.restore_from_tray(icon, item)
        hwnd = self._find_main_hwnd()

        if hwnd:
            try:
                user32 = getattr(self, '_foreground_user32', None)

                if user32 is None:
                    user32 = ctypes.WinDLL('user32', use_last_error=True)
                    user32.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
                    user32.SetForegroundWindow.argtypes = [ctypes.c_void_p]
                    user32.BringWindowToTop.argtypes = [ctypes.c_void_p]
                    self._foreground_user32 = user32

                # SW_RESTORE=9:最小化/最大化状态都回到常态,再置顶
                user32.ShowWindow(ctypes.c_void_p(hwnd), 9)
                user32.BringWindowToTop(ctypes.c_void_p(hwnd))
                user32.SetForegroundWindow(ctypes.c_void_p(hwnd))
            except Exception:
                log_exception('PYAS.bring_window_to_front')

    def restore_from_tray(self, icon=None, item=None):
        self._window_visible = True
        self._minimized = False

        if self._window:
            self._window.restore()
            self._window.show()

            hwnd = self._find_main_hwnd()

            if hwnd:
                self.user32.SetForegroundWindow(hwnd)

    def set_window(self, window):
        self._window = window

    def _find_main_hwnd(self):
        """按 PID+可见+面积定位主窗口,而不是按标题查找——
        pystray 托盘的隐藏消息窗口与主窗口同名,FindWindow 会找错。"""
        cached = getattr(self, "_cached_main_hwnd", None)

        if cached and self.user32.IsWindow(cached):
            return cached

        pid = os.getpid()
        found = []

        ENUMPROC = ctypes.WINFUNCTYPE(
            ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)

        def enum_callback(hwnd, lparam):
            owner = ctypes.wintypes.DWORD()
            self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))

            if owner.value != pid or not self.user32.IsWindowVisible(hwnd):
                return True

            rect = ctypes.wintypes.RECT()
            self.user32.GetWindowRect(hwnd, ctypes.byref(rect))
            found.append(((rect.right - rect.left) * (rect.bottom - rect.top), hwnd))
            return True

        callback = ENUMPROC(enum_callback)
        self.user32.EnumWindows(callback, 0)

        if not found:
            return None

        hwnd = max(found)[1]
        self._cached_main_hwnd = hwnd
        return hwnd

    def toggle_maximize(self):
        try:
            if not self._window:
                return False

            if getattr(self, "_maximized", False):
                self._window.restore()
                self._maximized = False
            else:
                self._window.maximize()
                self._maximized = True

            self._sync_maximize_icon()
            return self._maximized

        except Exception:
            log_exception("PYAS._MainMixin.toggle_maximize")
            return getattr(self, "_maximized", False)

    def _sync_maximize_icon(self):
        try:
            if self._window:
                self._window.evaluate_js(
                    "window.syncMaximizeIcon && window.syncMaximizeIcon("
                    + str(bool(getattr(self, "_maximized", False))).lower() + ")"
                )
        except Exception:
            log_exception("PYAS._MainMixin._sync_maximize_icon")

    CLASSIC_MENU_PATH = r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"

    def manage_classic_context_menu(self, enable):
        """恢复/移除 Win10 经典右键菜单(Win11 新菜单不显示未打包应用的传统
        注册表项,这是唯一能让扫描入口直接出现在右键的可行方式)。"""
        try:
            if enable:
                ok = self._reg_write(
                    winreg.HKEY_CURRENT_USER,
                    self.CLASSIC_MENU_PATH,
                    None,
                    winreg.REG_SZ,
                    "",
                )
            else:
                ok = self._reg_delete(winreg.HKEY_CURRENT_USER, self.CLASSIC_MENU_PATH)

            if not ok:
                self.write_log(
                    "WARN",
                    "register_context_menu",
                    detail="classic context menu registry write failed",
                    success=False,
                )
                return False

            explorer = self._find_windows_tool("explorer.exe")
            self._run_windows_tool(
                ("taskkill.exe",),
                ["/F", "/IM", "explorer.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.5)

            if explorer:
                subprocess.Popen([explorer])

            self.write_log(
                "INFO",
                "register_context_menu",
                detail=f"classic context menu {'enabled' if enable else 'disabled'}",
            )
            return True

        except Exception:
            log_exception("PYAS._MainMixin.manage_classic_context_menu")
            return False

    def minimize(self):
        self._minimized = True

        if self._window:
            self._window.minimize()
        else:
            hwnd = self._find_main_hwnd()

            if hwnd:
                self.user32.ShowWindow(hwnd, 6)

    def system_animation_enabled(self):
        """系统是否开启了「在 Windows 中显示动画」。

        开着就把最大化/最小化的过渡交给 DWM(和资源管理器一致);
        关着时前端才退回自己的 CSS 动画 —— 否则用户会看到硬切。"""
        try:
            # 不能用 ctypes.wintypes.BOOL:ctypes.wintypes 要显式 import,
            # 直接用会 AttributeError,被 except 吞掉 —— 结果永远是 False,
            # 表现就是"系统动画明明开着却仍走自定义动画"。
            enabled = ctypes.c_int()
            # SPI_GETCLIENTAREAANIMATION = 0x1042
            if self.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(enabled), 0):
                return bool(enabled.value)

            log_exception('PYAS.system_animation_enabled:SPI 返回 0')
        except Exception:
            log_exception('PYAS.system_animation_enabled')

        return False

    # 最小窗口尺寸(与 WM_GETMINMAXINFO 一致,JS 侧也按这个夹)
    MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT = 720, 560

    def resize_debug(self, message):
        """前端缩放链路的诊断落点(只写日志,不参与逻辑)。"""
        logging.getLogger('PYAS.Window').info('resize: %s', str(message)[:200])
        return True

    def window_rect(self):
        """返回 [left, top, right, bottom](屏幕坐标),给 JS 缩放时做基准。"""
        hwnd = self._find_main_hwnd()

        if not hwnd:
            return None

        rect = self.RECT()

        if not self.user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            return None

        return [rect.left, rect.top, rect.right, rect.bottom]

    def set_window_rect(self, left, top, width, height):
        """摆窗口到指定位置/尺寸,返回状态字符串,便于前端 HUD 直接显示。

        用 SetWindowPos 而不是 pywebview 的 resize():后者走 WinForms 的尺寸协商,
        每帧一次会明显发涩。SetWindowPos 失败时退回 MoveWindow。
        """
        hwnd = self._find_main_hwnd()

        if not hwnd:
            try:
                hwnd = find_main_window(PYAS_WINDOW_TITLE, own_pid=os.getpid())
            except Exception:
                hwnd = None

        if not hwnd:
            return 'no-hwnd'

        try:
            left, top = int(left), int(top)
            width = max(int(width), self.MIN_WINDOW_WIDTH)
            height = max(int(height), self.MIN_WINDOW_HEIGHT)

            user32 = getattr(self, '_rect_user32', None)

            if user32 is None:
                # 独立句柄 + 显式 argtypes,不与 _resize_user32 混用:
                # 混用时谁先建谁决定 argtypes,后建的一方拿到的是没声明的函数。
                user32 = ctypes.WinDLL('user32', use_last_error=True)
                user32.SetWindowPos.argtypes = [
                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                    ctypes.c_int, ctypes.c_int, ctypes.c_uint,
                ]
                user32.SetWindowPos.restype = ctypes.c_bool
                user32.MoveWindow.argtypes = [
                    ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                    ctypes.c_int, ctypes.c_int, ctypes.c_bool,
                ]
                user32.MoveWindow.restype = ctypes.c_bool
                self._rect_user32 = user32

            SWP_NOZORDER, SWP_NOACTIVATE = 0x0004, 0x0010

            if user32.SetWindowPos(
                ctypes.c_void_p(hwnd), None, left, top, width, height,
                SWP_NOZORDER | SWP_NOACTIVATE,
            ):
                return 'ok'

            err = ctypes.get_last_error()

            if user32.MoveWindow(ctypes.c_void_p(hwnd), left, top, width, height, True):
                return 'ok-move'

            return 'fail hwnd=0x%x err=%d move_err=%d' % (
                hwnd, err, ctypes.get_last_error()
            )
        except Exception as exc:
            log_exception('PYAS.set_window_rect')
            return 'except ' + type(exc).__name__

    def begin_window_resize(self, direction):
        """把一次鼠标按下转成系统的模态缩放循环。

        无边框窗口没有可拖的边框,JS 热区按下时只调用这里一次;
        之后由 Windows 自己的缩放循环接管 —— 拖动过程中**没有任何桥调用**,
        所以不会出现旧方案(每帧 resize)那种卡顿。

        两个前提缺一不可:
          1. 窗口必须有 WS_THICKFRAME(WindowHook.hook 里补),否则系统不认这是一次缩放;
          2. SendMessage 会一直阻塞到用户松手,所以必须丢到后台线程,
             不能让桥调用线程被卡住(否则前端拿不到返回、按钮像点了没反应)。
        """
        ht = self._RESIZE_HITTEST.get(str(direction or '').lower())

        if not ht:
            return False

        hwnd = self._find_main_hwnd()

        if not hwnd:
            logging.getLogger('PYAS.Window').info('begin_window_resize: main hwnd not found')
            return False

        if getattr(self, '_maximized', False):
            # 最大化状态下窗口不可缩放,先还原
            self.user32.ShowWindow(hwnd, 9)
            self._maximized = False

        user32 = getattr(self, '_resize_user32', None)

        if user32 is None:
            # 独立句柄:argtypes 只设在这个副本上,不污染 ctypes.windll 的全局函数
            user32 = ctypes.WinDLL('user32', use_last_error=True)
            user32.ReleaseCapture.argtypes, user32.ReleaseCapture.restype = [], ctypes.c_bool
            user32.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
            user32.SendMessageW.restype = ctypes.c_void_p
            self._resize_user32 = user32

        def _enter_resize_loop():
            try:
                user32.ReleaseCapture()
                # 等价于"在边框左上角按下左键":系统接管,直到用户松手
                user32.SendMessageW(ctypes.c_void_p(hwnd), 0x00A1, ctypes.c_void_p(ht), None)
                logging.getLogger('PYAS.Window').info('window resize loop finished ht=%s', ht)
            except Exception:
                log_exception('PYAS.begin_window_resize.loop')

        logging.getLogger('PYAS.Window').info('begin_window_resize dir=%s ht=%s', direction, ht)
        threading.Thread(target=_enter_resize_loop, daemon=True).start()
        return True

    def hide_window(self):
        self._window_visible = False

        if self._window:
            self._window.hide()

    def restart_application(self):
        """Relaunch so a saved policy takes effect; policy is read only at start.

        The launcher waits for this process to disappear before starting the new
        instance. Starting it immediately would hit the single-instance mutex and
        forward to the dying process, which looks exactly like a failed restart.
        """
        if getattr(self, "closing", False):
            return False

        launcher = os.path.join(os.path.dirname(sys.executable), "PYAS_Launcher.exe")

        # A development run has no launcher, so it has no way to wait for this
        # process to exit; report failure instead of pretending to restart.
        if not getattr(sys, "frozen", False) or not os.path.isfile(launcher):
            return False

        try:
            subprocess.Popen(
                [launcher, "--restart", str(os.getpid())],
                cwd=os.path.dirname(launcher),
                creationflags=0x00000008 | 0x08000000,  # DETACHED_PROCESS | CREATE_NO_WINDOW
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        except Exception:
            log_exception("PYAS._MainMixin.restart_application")
            return False

        logging.getLogger("PYAS.Policy").info(
            "Restart requested to apply the saved policy (pid %s)", os.getpid()
        )
        self.start_daemon_thread(self._restart_after_reply)
        return True

    def _restart_after_reply(self):
        # The bridge delivers this call's result over the same channel; exiting
        # sooner leaves the page with a rejected promise and a dead button.
        time.sleep(0.6)

        try:
            closed = self.close()
        except Exception:
            log_exception("PYAS._MainMixin._restart_after_reply")
            os._exit(0)

        if closed is False:
            # close() refused to exit (a driver could not be stopped), so the page
            # is still waiting on "Restarting…" with its only button disabled.
            try:
                window = getattr(self, "_window", None)

                if window:
                    window.evaluate_js("window.pyasPolicyRestartFailed && window.pyasPolicyRestartFailed()")
            except Exception:
                log_exception("PYAS._MainMixin._restart_after_reply.notify")

    def restart_application_elevated(self, notice_title, notice_body):
        """弹 UAC 以管理员令牌重启自身,用于"开关需要提权才生效"的场景。

        进程溯源/行为防护的 ETW 消费者必须在提权进程内建会话,进程内切换
        做不到 —— 与 autostart 的 ShellExecuteExW 提权同一套做法:经提权的
        launcher(--restart <pid>)等本实例退出后接管,新实例继承管理员令牌,
        引擎初始化读到已持久化的开关后自动拉起消费者。用户拒绝 UAC 返回
        False,调用方回拨开关;dev 运行没有 launcher,同样返回 False。
        """
        if getattr(self, "closing", False):
            return False

        launcher = os.path.join(os.path.dirname(sys.executable), "PYAS_Launcher.exe")

        if not getattr(sys, "frozen", False) or not os.path.isfile(launcher):
            return False

        class _Icon(ctypes.Union):
            _fields_ = [("icon", ctypes.wintypes.HANDLE), ("monitor", ctypes.wintypes.HANDLE)]

        class _ExecuteInfo(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.wintypes.DWORD),
                ("fMask", ctypes.wintypes.ULONG),
                ("hwnd", ctypes.wintypes.HWND),
                ("lpVerb", ctypes.wintypes.LPCWSTR),
                ("lpFile", ctypes.wintypes.LPCWSTR),
                ("lpParameters", ctypes.wintypes.LPCWSTR),
                ("lpDirectory", ctypes.wintypes.LPCWSTR),
                ("nShow", ctypes.c_int),
                ("hInstApp", ctypes.wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p),
                ("lpClass", ctypes.wintypes.HKEY),
                ("hkeyClass", ctypes.wintypes.HKEY),
                ("dwHotKey", ctypes.wintypes.DWORD),
                ("icon", _Icon),
                ("hProcess", ctypes.wintypes.HANDLE),
            ]

        info = _ExecuteInfo()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = 0x00000040 | 0x00000400  # NOASYNC | FLAG_DDEWAIT:拿到 hProcess 即返回,不等待
        info.lpVerb = "runas"
        info.lpFile = launcher
        info.lpParameters = f"--restart {os.getpid()}"
        info.nShow = 0

        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_ExecuteInfo)]
        shell32.ShellExecuteExW.restype = ctypes.wintypes.BOOL

        try:
            if not shell32.ShellExecuteExW(ctypes.byref(info)):
                error = ctypes.get_last_error()

                if error == 1223:  # ERROR_CANCELLED:用户在 UAC 里点了「否」
                    return False

                raise ctypes.WinError(error)
        except Exception:
            log_exception("PYAS._MainMixin.restart_application_elevated")
            return False

        # 开关值在 update_config 的正常路径里先落盘,这里只负责让位
        self.dispatch_notification(notice_title, notice_body)
        self.start_daemon_thread(self._restart_after_reply)
        return True

    def restart_to_apply_policy(self):
        """策略保存后的重启:非提权走 UAC 提权重启(新策略里的防护开关需要
        管理员令牌),已提权则同级重启即可。"""
        from PYAS_ETW import is_elevated

        if is_elevated():
            return self.restart_application()

        title = self._loc({
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
        })
        body = self._loc({
            "traditional_switch": "即將以管理員身份重啟 PYAS 以套用新的安全策略；重啟後防護開關自動生效。",
            "simplified_switch": "即将以管理员身份重启 PYAS 以应用新的安全策略；重启后防护开关自动生效。",
            "english_switch": "PYAS will restart with administrator rights to apply the new security policy; protection switches take effect automatically after the restart.",
            "japanese_switch": "新しいセキュリティポリシーを適用するため、PYAS を管理者権限で再起動します。再起動後は保護スイッチが自動的に有効になります。",
            "korean_switch": "새 보안 정책을 적용하기 위해 PYAS를 관리자 권한으로 다시 시작합니다. 다시 시작 후 보호 스위치가 자동으로 적용됩니다.",
            "french_switch": "PYAS va redémarrer avec des droits administrateur pour appliquer la nouvelle stratégie de sécurité ; les interrupteurs prendront effet automatiquement après le redémarrage.",
            "spanish_switch": "PYAS se reiniciará con permisos de administrador para aplicar la nueva directiva de seguridad; los interruptores surten efecto automáticamente tras el reinicio.",
            "hindi_switch": "नई सुरक्षा नीति लागू करने के लिए PYAS व्यवस्थापक अधिकारों के साथ पुनः प्रारंभ होगा; पुनः प्रारंभ के बाद सुरक्षा स्विच स्वतः प्रभावी होंगे।",
            "arabic_switch": "سيُعاد تشغيل PYAS بصلاحيات المسؤول لتطبيق نهج الأمان الجديد؛ تصبح مفاتيح الحماية سارية تلقائيًا بعد إعادة التشغيل.",
            "russian_switch": "PYAS перезапустится с правами администратора для применения новой политики безопасности; переключатели защиты вступят в силу автоматически после перезапуска.",
            "slovenian_switch": "PYAS se bo znova zagnal s skrbniškimi pravicami za uporabo nove varnostne politike; zaščitna stikala veljajo samodejno po ponovnem zagonu.",
        })
        return self.restart_application_elevated(title, body)

    def destroy_window_with_timeout(self, window, timeout=1.0):
        if not window:
            return

        done = threading.Event()

        def destroy_window():
            try:
                window.destroy()
            except Exception:
                log_exception("PYAS._MainMixin.destroy_window_with_timeout.destroy_window:315")
                pass
            finally:
                done.set()

        threading.Thread(target=destroy_window, daemon=True).start()
        done.wait(timeout)

    def close(self, *args, uninstall_driver=False, **kwargs):
        if getattr(self, "closing", False):
            return True

        self.closing = True

        with self.lock_config:
            driver_enabled = self.pyas_config.get("driver_switch", False)

        driver_loaded = driver_enabled or self.check_system_driver()

        if uninstall_driver:
            driver_stopped, driver_error = self.uninstall_system_driver()
        elif driver_loaded:
            driver_stopped = self.stop_system_driver()
            driver_error = 0 if driver_stopped else 1051
        else:
            driver_stopped, driver_error = True, 0

        if not driver_stopped:
            self.closing = False
            action = "uninstall" if uninstall_driver else "unload"
            self.write_log(
                "WARN",
                "Driver Protection",
                detail=f"Controlled {action} failed: 0x{driver_error & 0xFFFFFFFF:08X}",
                success=False,
            )

            if self._window:
                try:
                    self._window.show()
                except Exception:
                    log_exception("PYAS._MainMixin.close:348")
                    pass

            return False

        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except Exception:
                log_exception("PYAS._MainMixin.close:355")
                pass

            self.tray_icon = None

        self.cancel_pending_threats()
        window = self._window
        self._window = None

        if window:
            try:
                window.hide()
            except Exception:
                log_exception("PYAS._MainMixin.close:364")
                pass

        with self.lock_config:
            self.pyas_config["process_switch"] = False
            self.pyas_config["document_switch"] = False
            self.pyas_config["system_switch"] = False
            self.pyas_config["driver_switch"] = False
            self.pyas_config["network_switch"] = False

        self._cancel_pending_file_tasks()
        scheduler = getattr(self, "file_scheduler", None)

        if scheduler:
            scheduler.close()

        self.cloud_cancel_event.set()

        # 先 CancelIoEx 中止挂起读再关句柄(见 stop_dir_watcher 注释)
        if hasattr(self, "stop_dir_watcher"):
            self.stop_dir_watcher()

            if hasattr(self, "virus_lock"):
                for file_path, (fd, lock_size) in list(self.virus_lock.items()):
                    try:
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, lock_size)
                    except Exception:
                        log_exception("PYAS._MainMixin.close:388")
                        pass

                    try:
                        os.close(fd)
                    except Exception:
                        log_exception("PYAS._MainMixin.close:392")
                        pass

                self.virus_lock.clear()

        with self.lock_proc:
            if hasattr(self, "suspended_procs"):
                for h in list(self.suspended_procs):
                    try:
                        self.ntdll.NtResumeProcess(h)
                        self.kernel32.CloseHandle(h)
                    except Exception:
                        log_exception("PYAS._MainMixin.close:402")
                        pass

                self.suspended_procs.clear()

        for mutex_name in ("h_mutex", "h_recovery_mutex"):
            handle = getattr(self, mutex_name, None)

            if handle:
                try:
                    self.kernel32.CloseHandle(handle)
                except Exception:
                    log_exception("PYAS._MainMixin.close:411")
                    pass

                setattr(self, mutex_name, None)

        self.flush_logs_now()
        self.destroy_window_with_timeout(window)
        os._exit(0)

    def report_ui_error(self, stage, message):
        logging.getLogger("PYAS.Startup").warning(
            "UI stage=%s: %s", str(stage)[:80], str(message)[:2000]
        )
        return True

    def init_ui_ready(self):
        logging.getLogger("PYAS.Startup").info("Python UI bridge ready")
        self.ui_ready_event.set()

        with self.lock_config:
            if self.engine_initialized:
                return

            self.engine_initialized = True

        self.start_daemon_thread(self.init_engine_thread)
        self.start_daemon_thread(self.notification_permission_watch)

    def notification_permission_watch(self):
        time.sleep(4)

        try:
            status = self.check_notification_permission()
        except Exception:
            log_exception("PYAS._MainMixin.notification_permission_watch")
            return

        if not status.get("supported") or status.get("enabled", True):
            return

        self.write_log(
            "WARN",
            "Notification Permission",
            detail="Windows notifications are disabled",
            success=False,
        )

        title = self._loc(
            {
                "traditional_switch": "提示",
                "simplified_switch": "提示",
                "english_switch": "Prompt",
                "japanese_switch": "プロンプト",
                "korean_switch": "프롬프트",
                "french_switch": "Indication",
                "spanish_switch": "Aviso",
                "hindi_switch": "सुझाव",
                "arabic_switch": "تلميح",
                "russian_switch": "Подсказка",
                "slovenian_switch": "Namig",
            }
        )
        message = self._loc(
            {
                "traditional_switch": "Windows 通知權限已被禁用，攔截通知將無法顯示。\n是否開啟系統通知設定？",
                "simplified_switch": "Windows 通知权限已被禁用，拦截通知将无法显示。\n是否打开系统通知设置？",
                "english_switch": "Windows notifications are disabled. Threat notifications will not be shown.\nOpen Windows notification settings now?",
                "japanese_switch": "Windows の通知が無効になっています。脅威の通知は表示されません。\n通知設定を開きますか？",
                "korean_switch": "Windows 알림이 비활성화되어 있습니다. 위협 알림이 표시되지 않습니다.\n알림 설정을 여시겠습니까?",
                "french_switch": "Les notifications Windows sont désactivées. Les alertes de menaces ne seront pas affichées.\nOuvrir les paramètres de notification ?",
                "spanish_switch": "Las notificaciones de Windows están desactivadas. Las alertas de amenazas no se mostrarán.\n¿Abrir la configuración de notificaciones?",
                "hindi_switch": "Windows अधिसूचनाएँ अक्षम हैं। खतरे की सूचनाएँ नहीं दिखेंगी।\nअभी Windows अधिसूचना सेटिंग खोलें?",
                "arabic_switch": "إشعارات Windows معطلة. لن تظهر تنبيهات التهديدات.\nهل تريد فتح إعدادات الإشعارات الآن؟",
                "russian_switch": "Уведомления Windows отключены. Оповещения об угрозах не будут отображаться.\nОткрыть настройки уведомлений?",
                "slovenian_switch": "Obvestila Windows so onemogočena. Opozorila o grožnjah ne bodo prikazana.\nAli želite odpreti nastavitve obvestil?",
            }
        )

        if self.show_confirm(title, message):
            self.open_notification_settings()

    def get_block_action_title(self, action):
        titles = {
            "Process Block": {
                "traditional_switch": "進程防護",
                "simplified_switch": "进程防护",
                "english_switch": "Process Protection",
                "japanese_switch": "プロセス保護",
                "korean_switch": "프로세스 보호",
                "french_switch": "Protection des Processus",
                "spanish_switch": "Protección de Procesos",
                "hindi_switch": "प्रक्रिया सुरक्षा",
                "arabic_switch": "حماية العمليات",
                "russian_switch": "Защита процессов",
                "slovenian_switch": "Zaščita procesov",
            },
            "Process DLL Block": {
                "traditional_switch": "記憶體防護",
                "simplified_switch": "内存防护",
                "english_switch": "Memory Protection",
                "japanese_switch": "メモリ保護",
                "korean_switch": "메모리 보호",
                "french_switch": "Protection de la mémoire",
                "spanish_switch": "Protección de memoria",
                "hindi_switch": "मेमोरी सुरक्षा",
                "arabic_switch": "حماية الذاكرة",
                "russian_switch": "Защита памяти",
                "slovenian_switch": "Zaščita pomnilnika",
            },
            "File Block": {
                "traditional_switch": "檔案防護",
                "simplified_switch": "文件防护",
                "english_switch": "File Protection",
                "japanese_switch": "ファイル保護",
                "korean_switch": "파일 보호",
                "french_switch": "Protection des Fichiers",
                "spanish_switch": "Protección de Archivos",
                "hindi_switch": "फ़ाइल सुरक्षा",
                "arabic_switch": "حماية الملفات",
                "russian_switch": "Защита файлов",
                "slovenian_switch": "Zaščita datotek",
            },
            "Network Block": {
                "traditional_switch": "網路防護",
                "simplified_switch": "网络防护",
                "english_switch": "Network Protection",
                "japanese_switch": "ネットワーク保護",
                "korean_switch": "네트워크 보호",
                "french_switch": "Protection Réseau",
                "spanish_switch": "Protección de Red",
                "hindi_switch": "नेटवर्क सुरक्षा",
                "arabic_switch": "حماية الشبكة",
                "russian_switch": "Сетевая защита",
                "slovenian_switch": "Omrežna zaščita",
            },
            "Driver Block": {
                "traditional_switch": "驅動防護",
                "simplified_switch": "驱动防护",
                "english_switch": "Driver Protection",
                "japanese_switch": "ドライバー保護",
                "korean_switch": "드라이버 보호",
                "french_switch": "Protection des Pilotes",
                "spanish_switch": "Protección de Controladores",
                "hindi_switch": "ड्राइवर सुरक्षा",
                "arabic_switch": "حماية برامج التشغيل",
                "russian_switch": "Защита драйверов",
                "slovenian_switch": "Zaščita gonilnikov",
            },
            "Deferred Scan Block": {
                "traditional_switch": "檔案防護",
                "simplified_switch": "文件防护",
                "english_switch": "File Protection",
                "japanese_switch": "ファイル保護",
                "korean_switch": "파일 보호",
                "french_switch": "Protection des Fichiers",
                "spanish_switch": "Protección de Archivos",
                "hindi_switch": "फ़ाइल सुरक्षा",
                "arabic_switch": "حماية الملفات",
                "russian_switch": "Защита файлов",
                "slovenian_switch": "Zaščita datotek",
            },
        }
        return self._loc(titles.get(action, {}))

    def dispatch_notification(self, title, message):
        """通知渠道分流:system=Windows 标准通知(托盘),custom=程序内通知窗。"""
        with self.lock_config:
            channel = self.pyas_config.get("notify_channel", "system")

        if channel == "custom":
            if self.show_custom_notification(title, message):
                return

        try:
            if self.tray_icon:
                self.tray_icon.notify(message, title)
        except Exception:
            log_exception("PYAS._MainMixin.dispatch_notification")

    def trigger_block_notification(self, action, source, target, code):
        if action not in [
            "Process Block",
            "Process DLL Block",
            "File Block",
            "Network Block",
            "Driver Block",
        ]:
            return

        # 智能体关联审计:自动拦截来源命中智能体指纹时留痕(交互告警由
        # request_block_decision 落同款审计,两条路径合起来全覆盖)
        try:
            self.note_agent_for_path(source)
        except Exception:
            log_exception("PYAS.trigger_block_notification.agent_audit")

        path = source or ""
        messages = {
            "traditional_switch": f"已自動攔截: {path}",
            "simplified_switch": f"已自动拦截: {path}",
            "english_switch": f"Blocked automatically: {path}",
            "japanese_switch": f"自動ブロックしました: {path}",
            "korean_switch": f"자동 차단됨: {path}",
            "french_switch": f"Blocage automatique : {path}",
            "spanish_switch": f"Bloqueado automáticamente: {path}",
            "hindi_switch": f"स्वतः ब्लॉक किया गया: {path}",
            "arabic_switch": f"تم الحظر تلقائيًا: {path}",
            "russian_switch": f"Заблокировано автоматически: {path}",
            "slovenian_switch": f"Samodejno blokirano: {path}",
        }

        title = self.get_block_action_title(action)
        message = self._loc(messages)
        self.dispatch_notification(title, message)

    def show_notification(self, title, message):
        self.dispatch_notification(title, message)

    def show_alert(self, title, message, style="info"):
        flags = 0x00000000 | (
            0x00000010 if style == "error" else 0x00000030 if style == "warning" else 0x00000040
        )
        self.user32.MessageBoxW(0, message, title, flags)
        return True

    def ask_confirmation(self, title, message):
        """置顶的「是/否」询问框;独立线程调用安全(自泵模态循环)。
        返回 True=用户选「是」。启动核对等后台流程用它向用户求确认。"""
        if getattr(self, "closing", False):
            return False

        result = self.user32.MessageBoxW(
            0, message, title, 0x00000004 | 0x00000020 | 0x00040000 | 0x00010000
        )  # MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND
        return result == 6  # IDYES

    def show_confirm(self, title, message):
        return self.user32.MessageBoxW(0, message, title, 0x00000004 | 0x00000020) == 6

    def register_context_menu(self, enable, retry=False):
        paths = [
            r"Software\Classes\*\shell\PYAS_Scan",
            r"Software\Classes\Directory\shell\PYAS_Scan",
        ]
        cmd_path = (
            f'"{self.file_pyas}"'
            if getattr(sys, "frozen", False)
            else f'"{self.python}" "{self.file_pyas}"'
        )

        try:
            success = True

            for path in paths:
                if enable:
                    success = (
                        self._reg_write(
                            winreg.HKEY_CURRENT_USER,
                            path,
                            None,
                            winreg.REG_SZ,
                            "PYAS Security Scan",
                        )
                        and success
                    )
                    success = (
                        self._reg_write(
                            winreg.HKEY_CURRENT_USER, path, "Icon", winreg.REG_SZ, f"{cmd_path},0"
                        )
                        and success
                    )
                    success = (
                        self._reg_write(
                            winreg.HKEY_CURRENT_USER,
                            rf"{path}\command",
                            None,
                            winreg.REG_SZ,
                            f'{cmd_path} -scan "%1"',
                        )
                        and success
                    )
                else:
                    for entry in (rf"{path}\command", path):
                        try:
                            with winreg.OpenKey(
                                winreg.HKEY_CURRENT_USER, entry, 0, winreg.KEY_READ
                            ):
                                pass
                        except FileNotFoundError:
                            continue

                        success = self._reg_delete(winreg.HKEY_CURRENT_USER, entry) and success

            if not success:
                self.write_log(
                    "WARN",
                    "register_context_menu",
                    detail="Registry operation failed",
                    success=False,
                )

            modern_success = self.register_modern_context_menu(enable, retry=retry)
            modern_supported = sys.getwindowsversion().build >= 22000 and getattr(sys, 'frozen', False)
            self._context_menu_mode = (
                'modern' if enable and modern_supported and modern_success else
                'legacy' if enable and success else 'failed' if enable else
                'disabled' if modern_success and success else 'failed'
            )
            if getattr(self, 'ui_queue', None) is not None:
                self.ui_queue.put('window.refreshContextMenuStatus?.();')
            if not enable:
                # Turning scanning off must remove both entries.
                return modern_success and success

            if success and not modern_success and not getattr(self, '_menu_attempt_skipped', False):
                self.write_log(
                    "INFO", "Context Menu Fallback",
                    detail="Modern menu registration failed; scanning remains available in the original context menu (Show more options on Windows 11).",
                    success=True,
                )
            # The modern helper is a no-op on Windows 10/source runs; it must
            # not conceal a failed original-menu registration there.
            return success or (modern_supported and modern_success)
        except Exception as error:
            log_exception("PYAS._MainMixin.register_context_menu:523")
            self.write_log("WARN", "register_context_menu", detail=str(error), success=False)
            return False

    def get_context_menu_status(self):
        notice = ''
        state = getattr(self, '_menu_registration_state', None)
        if state:
            try:
                notice = state.take_notice()
            except Exception:
                log_exception('PYAS.menu_notice_state')
        mode = getattr(self, '_context_menu_mode', 'pending')
        if mode == 'modern' and getattr(self, 'pyas_config', {}).get('classic_menu_switch'):
            mode = 'legacy'
        return {'mode': mode, 'notice': notice}

    def register_modern_context_menu(self, enable, retry=False):
        self._menu_attempt_skipped = False
        if sys.getwindowsversion().build < 22000 or not getattr(sys, 'frozen', False):
            return True
        state = getattr(self, '_menu_registration_state', None)
        if state is None:
            state = self._menu_registration_state = MenuRegistrationState(self.path_pyas)
        if enable and not retry and state.failed():
            self._menu_attempt_skipped = True
            return False

        def remember(success, error=''):
            try:
                if enable or success:
                    state.record(success, error)
            except Exception:
                log_exception('PYAS.menu_registration_state')
            return success
        menu_path = os.path.join(self.path_pyas, 'Menu')
        script = os.path.join(menu_path, 'register_menu.ps1' if enable else 'unregister_menu.ps1')
        if not os.path.isfile(script):
            self.write_log('WARN', 'Modern Context Menu', detail='Registration files are missing', success=False)
            return remember(False, 'Registration files are missing')
        command = [os.path.join(self.path_system, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script]
        if enable:
            command.extend(['-ExternalLocation', self.path_pyas])
        try:
            result = subprocess.run(command, capture_output=True,
                timeout=90, creationflags=subprocess.CREATE_NO_WINDOW)
            detail = (decode_process_output(result.stdout) + decode_process_output(result.stderr)).strip()[:1500]
            ok = result.returncode == 0
            # 幂等路径(PowerShell 判定已注册后直接 exit 0)没有任何输出,
            # 这里补一条固定状态文案,否则日志详情是空的
            if ok and not detail:
                detail = 'Context menu registered' if enable else 'Context menu unregistered'
            self.write_log('INFO' if ok else 'WARN', 'Modern Context Menu',
                detail=detail,
                success=ok)
            return remember(ok, detail if result.returncode else '')
        except Exception as error:
            log_exception('PYAS.register_modern_context_menu')
            return remember(False, str(error))

    def trigger_context_scan(self, target):
        if self._window:
            self._window.evaluate_js(
                f"if(window.triggerContextScan) window.triggerContextScan({json.dumps(target.replace(os.sep, '/'))});"
            )

    def on_drop(self, e):
        def _process_drop():
            try:
                files = e.get("dataTransfer", {}).get("files", [])
                paths = [f.get("pywebviewFullPath") for f in files if f.get("pywebviewFullPath")]

                if paths and self._window:
                    self._window.evaluate_js(
                        f"if(window.triggerContextScan) window.triggerContextScan({json.dumps(paths)});"
                    )

            except Exception as ex:
                log_exception("PYAS._MainMixin.on_drop._process_drop:540")
                self.write_log("WARN", "on_drop", detail=str(ex), success=False)

        threading.Thread(target=_process_drop, daemon=True).start()

    def select_files(self, file_types=None):
        if self._window:
            kwargs = {"allow_multiple": True}

            if file_types:
                kwargs["file_types"] = tuple(file_types)

            return (
                self._window.create_file_dialog(getattr(webview, "OPEN_DIALOG", 10), **kwargs) or []
            )

        return []

    def select_folder(self):
        if self._window:
            return self._window.create_file_dialog(getattr(webview, "FOLDER_DIALOG", 20)) or []

        return []

    def open_file_location(self, file_path):
        if not file_path:
            return False

        expanded_path = os.path.expandvars(file_path).strip('"').strip("'")
        reg_prefixes = ("HKLM", "HKCU", "HKCR", "HKU", "HKCC", "HKEY_")

        if expanded_path.upper().startswith(reg_prefixes):
            try:
                full_path = expanded_path

                if full_path.startswith("HKLM"):
                    full_path = full_path.replace("HKLM", "HKEY_LOCAL_MACHINE", 1)

                elif full_path.startswith("HKCU"):
                    full_path = full_path.replace("HKCU", "HKEY_CURRENT_USER", 1)

                elif full_path.startswith("HKCR"):
                    full_path = full_path.replace("HKCR", "HKEY_CLASSES_ROOT", 1)

                elif full_path.startswith("HKU"):
                    full_path = full_path.replace("HKU", "HKEY_USERS", 1)

                elif full_path.startswith("HKCC"):
                    full_path = full_path.replace("HKCC", "HKEY_CURRENT_CONFIG", 1)

                self._run_windows_tool(
                    ("taskkill.exe",),
                    ["/F", "/IM", "regedit.exe"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self._reg_write(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit",
                    "LastKey",
                    winreg.REG_SZ,
                    full_path,
                )
                regedit = self._find_windows_tool("regedit.exe")

                if not regedit:
                    return False

                subprocess.Popen([regedit])

                return True
            except Exception:
                log_exception("PYAS._MainMixin.open_file_location:597")
                pass

            return False

        if os.path.exists(expanded_path):
            try:
                clean_path = os.path.normpath(expanded_path)
                explorer = self._find_windows_tool("explorer.exe")

                if not explorer:
                    return False

                subprocess.Popen([explorer, "/select,", clean_path])
                return True

            except Exception:
                log_exception("PYAS._MainMixin.open_file_location:610")
                pass

        return False

    def open_website(self):
        try:
            return webbrowser.open(self.pyas_config.get("api_host"))
        except Exception:
            log_exception("PYAS._MainMixin.open_website:617")
            return False

    def open_url(self, url):
        try:
            return webbrowser.open(url)
        except Exception:
            log_exception("PYAS._MainMixin.open_url:623")
            return False


class WindowAPI(_MainMixin, ScannerMixin, ToolsMixin, ProtectMixin):
    pass


def get_base_path():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)

    return os.path.dirname(os.path.abspath(__file__))


def get_frontend_asset_errors():
    base_path = get_base_path()
    required_files = [
        os.path.join("Interface", "templates", "index.html"),
        os.path.join("Interface", "static", "css", "style.css"),
        os.path.join("Interface", "static", "js", "i18n.js"),
        os.path.join("Interface", "static", "js", "main.js"),
        os.path.join("Interface", "static", "js", "theme.js"),
        os.path.join("Interface", "static", "js", "threat.js"),
        os.path.join("Interface", "static", "css", "threat.css"),
        os.path.join("Interface", "templates", "threat.html"),
    ]
    errors = []

    for rel_path in required_files:
        abs_path = os.path.join(base_path, rel_path)

        if not os.path.isfile(abs_path):
            errors.append(f"Missing UI asset: {rel_path}")
        elif os.path.getsize(abs_path) <= 0:
            errors.append(f"Empty UI asset: {rel_path}")

    return errors


def show_startup_error(message):
    try:
        ctypes.windll.user32.MessageBoxW(None, message, PYAS_WINDOW_TITLE, 0x00000010)
    except Exception:
        log_exception("PYAS.show_startup_error:662")
        pass


class NoCacheRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.join(get_base_path(), "Interface"), **kwargs)

    def log_message(self, format, *args):
        logging.getLogger("PYAS.Startup").info("HTTP %s: " + format, self.client_address[0], *args)

    def do_GET(self):
        if self.path == "/":
            self.path = "/templates/index.html"

        return super().do_GET()

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Expires", "0")
        self.send_header("Pragma", "no-cache")
        super().end_headers()


class _NCCALCSIZE_PARAMS(ctypes.Structure):
    """WM_NCCALCSIZE 的 lParam 结构:rgrc[0] 是待计算的窗口/客户区矩形。"""

    _fields_ = [("rgrc", RECT * 3), ("lppos", ctypes.c_void_p)]


class WindowHook:
    def __init__(self, title, api_ref=None):
        self.title, self.api_ref = title, api_ref
        self.old_wndproc = None
        self.WM_DPICHANGED = 0x02E0
        self.WM_NCHITTEST = 0x0084
        self.WM_CLOSE = 0x0010
        self.WM_COPYDATA = WM_COPYDATA
        self.WM_SYSCOMMAND = 0x0112
        self.WM_GETMINMAXINFO = 0x0024
        self.SC_CLOSE = 0xF060
        self.SC_MINIMIZE = 0xF020
        self.SC_MAXIMIZE = 0xF030
        self.SC_RESTORE = 0xF120
        self.HTCAPTION = 2
        self.MIN_WINDOW_WIDTH = 720
        self.MIN_WINDOW_HEIGHT = 560
        self.GWLP_WNDPROC = -4

        self.RECT = RECT
        self.NCCALCSIZE_PARAMS = _NCCALCSIZE_PARAMS
        self.WNDPROC = ctypes.WINFUNCTYPE(
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p
        )

        self.user32 = ctypes.windll.user32
        self.user32.FindWindowW.argtypes, self.user32.FindWindowW.restype = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
        ], ctypes.wintypes.HWND
        self.user32.CallWindowProcW.argtypes, self.user32.CallWindowProcW.restype = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ], ctypes.c_void_p
        self.user32.DefWindowProcW.argtypes, self.user32.DefWindowProcW.restype = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ], ctypes.c_void_p

        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.SetWindowLong, self.GetWindowLong = (
                self.user32.SetWindowLongPtrW,
                self.user32.GetWindowLongPtrW,
            )
        else:
            self.SetWindowLong, self.GetWindowLong = (
                self.user32.SetWindowLongW,
                self.user32.GetWindowLongW,
            )

        self.SetWindowLong.argtypes, self.SetWindowLong.restype = [
            ctypes.c_void_p,
            ctypes.c_int,
            self.WNDPROC,
        ], ctypes.c_void_p
        self.GetWindowLong.argtypes, self.GetWindowLong.restype = [
            ctypes.c_void_p,
            ctypes.c_int,
        ], ctypes.c_void_p
        self.new_wndproc_cb = self.WNDPROC(self.wndproc)

    def hook(self):
        if self.old_wndproc:
            return

        hwnd = find_main_window(self.title, own_pid=os.getpid())

        if hwnd:
            self.old_wndproc = self.GetWindowLong(hwnd, self.GWLP_WNDPROC)
            self.SetWindowLong(hwnd, self.GWLP_WNDPROC, self.new_wndproc_cb)

            # 补上最小化/最大化/可缩放位:无边框窗口默认这三样都没有,
            # 于是①点任务栏标签发来的 SC_MINIMIZE 被忽略、②DWM 不给最小化动画、
            # ③WM_NCLBUTTONDOWN + HTxxx 进不了缩放循环(窗口不是 sizable)。
            #
            # 注意不能复用 self.SetWindowLong:它的 argtypes 是按 SetWindowLongPtrW(GWLP_WNDPROC)
            # 声明的,第三参是 WNDPROC 函数指针;拿它写 GWL_STYLE 会 TypeError,
            # 而这里包了 try/except,失败是静默的 —— 样式根本没生效过。
            try:
                GWL_STYLE = -16
                WS_MINIMIZEBOX, WS_MAXIMIZEBOX, WS_THICKFRAME = 0x00020000, 0x00010000, 0x00040000
                style32 = ctypes.WinDLL('user32', use_last_error=True)
                style32.GetWindowLongW.argtypes = [ctypes.c_void_p, ctypes.c_int]
                style32.GetWindowLongW.restype = ctypes.c_long
                style32.SetWindowLongW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long]
                style32.SetWindowLongW.restype = ctypes.c_long
                before = style32.GetWindowLongW(ctypes.c_void_p(hwnd), GWL_STYLE) or 0
                after = before | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_THICKFRAME
                style32.SetWindowLongW(ctypes.c_void_p(hwnd), GWL_STYLE, after)
                applied = style32.GetWindowLongW(ctypes.c_void_p(hwnd), GWL_STYLE) or 0
                logging.getLogger('PYAS.Window').info(
                    'window style 0x%08x -> 0x%08x (readback 0x%08x)', before, after, applied
                )
            except Exception:
                log_exception('PYAS.WindowHook.hook:style')

            try:
                # Win11 显式圆角:窗口是 WS_POPUP 出身、THICKFRAME 是后补的,
                # DWM 不一定按应用窗口给它自动圆角;属性 33 = DWMWA_WINDOW_CORNER_
                # PREFERENCE,值 2 = DWMWCP_ROUND。Win10 无此属性(返回错误码),忽略
                dwm = ctypes.WinDLL('dwmapi', use_last_error=True)
                dwm.DwmSetWindowAttribute.argtypes = [
                    ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
                preference = ctypes.c_int(2)  # DWMWCP_ROUND
                dwm.DwmSetWindowAttribute(
                    ctypes.c_void_p(hwnd), 33, ctypes.byref(preference), 4)
            except Exception:
                log_exception('PYAS.WindowHook.hook:dwm')

            try:
                self.user32.ChangeWindowMessageFilterEx.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_uint,
                    ctypes.c_uint,
                    ctypes.c_void_p,
                ]

                # MSGFLT_ALLOW=1: 允许(可能未提权的)安装器等进程投递维护消息。
                # 上游原代码使用的 ChangeWindowMessageFilter(msg, 0) 参数非法,
                # 必然失败并导致 maintenance_channel_ready 永远为 False,
                # 使 -quit 的退出消息被窗口过程直接忽略。
                if not self.user32.ChangeWindowMessageFilterEx(
                    hwnd, PYAS_MAINTENANCE_MESSAGE, 1, None
                ):
                    raise OSError("Could not allow maintenance message channel")

                self.user32.ChangeWindowMessageFilterEx(hwnd, self.WM_COPYDATA, 1, None)
                self.maintenance_channel_ready = True
            except Exception:
                log_exception("PYAS.WindowHook.hook:732")
                pass

    def resync_after_restore(self):
        """还原后强制一次等尺寸 resize。

        WebView2 的 bounds 是在 WinForms 的 OnResize 里推过去的;从最小化还原时
        那一帧可能还按最小化前/占位尺寸画,表现为「窗口跳一下」。这里在还原后
        主动走一次 resize(尺寸不变),让子窗立刻按当前客户区重排。
        """
        time.sleep(0.05)
        window = getattr(self.api_ref, "_window", None)

        if window is None:
            return

        try:
            window.resize(int(round(window.width)), int(round(window.height)))
        except Exception:
            log_exception("PYAS.WindowHook.resync_after_restore")

    def call_default(self, hwnd, msg, wparam, lparam):
        if self.old_wndproc:
            return self.user32.CallWindowProcW(self.old_wndproc, hwnd, msg, wparam, lparam)

        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def wndproc(self, hwnd, msg, wparam, lparam):
        if msg == 0x0006 and self.api_ref:  # WM_ACTIVATE
            # 记下最近一次被激活的时间。托盘点击会把前台让给 explorer,
            # 等回调跑起来再问 GetForegroundWindow 已经晚了。
            if (wparam & 0xFFFF) != 0:
                self.api_ref._last_active_at = time.monotonic()
        if msg in (0x0231, 0x0232) and self.api_ref:  # WM_ENTER/EXITSIZEMOVE
            self.api_ref._window_interacting = msg == 0x0231
        if msg == PYAS_MAINTENANCE_MESSAGE:
            # maintenance_channel_ready 只作为诊断信息,不作为硬门:
            # 即使消息过滤器配置失败,退出/卸载链路也必须保持可用。
            if wparam not in PYAS_MAINTENANCE_COMMANDS or not self.api_ref:
                return 0

            uninstall = wparam in (PYAS_MESSAGE_QUIT, PYAS_MESSAGE_DRIVER_UNINSTALL)
            threading.Thread(
                target=self.api_ref.close, kwargs={"uninstall_driver": uninstall}, daemon=True
            ).start()
            return 1

        if msg == self.WM_COPYDATA:
            try:
                if not lparam:
                    return 0

                cds = COPYDATASTRUCT.from_address(lparam)

                if cds.dwData not in (PYAS_MESSAGE_SCAN, PYAS_MESSAGE_SHOW):
                    return 0

                if cds.dwData == PYAS_MESSAGE_SCAN and (
                    not cds.lpData or not 0 < cds.cbData <= 131072
                ):
                    return 0

                if cds.dwData == PYAS_MESSAGE_SCAN:
                    path = ctypes.string_at(cds.lpData, cds.cbData).decode("utf-8").strip("\x00")

                    if self.api_ref:
                        threading.Thread(target=self.api_ref.restore_from_tray, daemon=True).start()
                        threading.Thread(
                            target=self.api_ref.trigger_context_scan, args=(path,), daemon=True
                        ).start()

                elif cds.dwData == PYAS_MESSAGE_SHOW and self.api_ref:
                    threading.Thread(target=self.api_ref.restore_from_tray, daemon=True).start()

            except Exception:
                log_exception("PYAS.WindowHook.wndproc:762")
                pass

            return 1

        if msg == self.WM_SYSCOMMAND and self.api_ref:
            sc_value = wparam & 0xFFF0

            if sc_value == self.SC_MINIMIZE:
                # 无边框窗口没有 WS_MINIMIZEBOX,点任务栏按钮时系统发的 SC_MINIMIZE
                # 会被 WinForms 直接忽略(表现为「点了没反应」)。这里改走应用自己的
                # minimize():与标题栏按钮同一条路,还原时尺寸才不会丢。
                threading.Thread(target=self.api_ref.minimize, daemon=True).start()
                return 0

            if sc_value in (self.SC_MAXIMIZE, self.SC_RESTORE):
                self.api_ref._maximized = sc_value == self.SC_MAXIMIZE

                if sc_value == self.SC_RESTORE:
                    # 系统还原(任务栏 / Alt+Tab)也要清掉已最小化标记,
                    # 否则托盘点击会误判成还在最小化而重复还原。
                    self.api_ref._minimized = False

                if sc_value == self.SC_RESTORE:
                    threading.Thread(target=self.resync_after_restore, daemon=True).start()
                # evaluate_js waits for the WebView thread; never call it from
                # the native window procedure that thread may be waiting on.
                self.api_ref.ui_queue.put(
                    "window.syncMaximizeIcon && window.syncMaximizeIcon("
                    + str(self.api_ref._maximized).lower() + ");"
                )

        if msg == self.WM_CLOSE or (
            msg == self.WM_SYSCOMMAND and (wparam & 0xFFF0) == self.SC_CLOSE
        ):
            if self.api_ref and not getattr(self.api_ref, "closing", False):
                threading.Thread(target=self.api_ref.hide_window, daemon=True).start()
                return 0

            return self.call_default(hwnd, msg, wparam, lparam)

        if msg == 0x0083 and wparam:  # WM_NCCALCSIZE:客户区算法
            # 为了可缩放,窗口补了 WS_THICKFRAME;但系统会把客户区往里缩一圈边框,
            # 表现就是顶部一条白边(最小化还原后尤其明显,因为重算了一次布局)。
            # 这里声明没有非客户区:客户区 = 整个窗口矩形。
            # 用 IsZoomed 查实际状态,不要用 _maximized 标志:
            # 恢复(SC_RESTORE)时标志已经翻成 False,但系统仍会带最大化尺寸来算一次,
            # 按标志判断就会给普通窗口套上最大化补偿 → 顶部再出一条白边。
            if not self.user32.IsZoomed(ctypes.c_void_p(hwnd)):
                return 0

            # 最大化时窗口矩形比工作区大出边框厚度,不补偿就会把四边吃掉。
            try:
                params = ctypes.cast(lparam, ctypes.POINTER(self.NCCALCSIZE_PARAMS)).contents
                rect = params.rgrc[0]
                pad_x = self.user32.GetSystemMetrics(32) + self.user32.GetSystemMetrics(92)
                pad_y = self.user32.GetSystemMetrics(33) + self.user32.GetSystemMetrics(92)
                rect.left += pad_x
                rect.top += pad_y
                rect.right -= pad_x
                rect.bottom -= pad_y
            except Exception:
                log_exception('PYAS.WindowHook.wndproc:nccalcsize')

            return 0

        if msg == self.WM_NCHITTEST:
            x, y = lparam & 0xFFFF, (lparam >> 16) & 0xFFFF

            if x >= 32768:
                x -= 65536

            if y >= 32768:
                y -= 65536

            rect = self.RECT()
            self.user32.GetWindowRect(hwnd, ctypes.byref(rect))

            if rect.top <= y <= rect.top + 44 and rect.left <= x <= rect.right - 150:
                return self.HTCAPTION

        if msg == self.WM_GETMINMAXINFO:
            try:
                info = MINMAXINFO.from_address(lparam)
                info.ptMinTrackSize.x = self.MIN_WINDOW_WIDTH
                info.ptMinTrackSize.y = self.MIN_WINDOW_HEIGHT
                return 0
            except Exception:
                log_exception("PYAS.WindowHook.wndproc.getminmaxinfo")
                pass

        if msg == self.WM_DPICHANGED:
            try:
                rect = self.RECT.from_address(lparam)
                self.user32.SetWindowPos(
                    hwnd,
                    None,
                    rect.left,
                    rect.top,
                    rect.right - rect.left,
                    rect.bottom - rect.top,
                    0x0004 | 0x0010 | 0x0020,
                )
            except Exception:
                log_exception("PYAS.WindowHook.wndproc:788")
                pass

        return self.call_default(hwnd, msg, wparam, lparam)


class StartupHTTPServer(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        logging.getLogger("PYAS.Startup").exception("HTTP request failed: %s", client_address)


def start_api(port_container, error_container, ready_event):
    logger = logging.getLogger("PYAS.Startup")

    try:
        with StartupHTTPServer(("127.0.0.1", 0), NoCacheRequestHandler) as httpd:
            port_container.append(httpd.server_address[1])
            logger.info("HTTP listener ready: 127.0.0.1:%s", port_container[0])
            ready_event.set()
            httpd.serve_forever()
    except Exception as e:
        logger.exception("HTTP listener failed")
        error_container.append(str(e))
        ready_event.set()


def verify_ui_server(port):
    from urllib.request import build_opener, ProxyHandler

    opener = build_opener(ProxyHandler({}))

    for path in ("/", "/static/css/style.css", "/static/js/i18n.js", "/static/js/main.js"):
        with opener.open(f"http://127.0.0.1:{port}{path}", timeout=3) as response:
            if response.status != 200 or not response.read(1):
                raise RuntimeError(f"UI HTTP health check failed: {path}")

    logging.getLogger("PYAS.Startup").info("HTTP UI health checks passed")


def start_ui():
    logger = logging.getLogger("PYAS.Startup")
    hide_on_start = "-h" in sys.argv or "-hide" in sys.argv
    init_width, init_height = 980, 670
    stage = "assets"
    js_api = None
    webview_completed = threading.Event()
    recovery_lock = threading.Lock()

    def fail_startup(reason, recover=False):
        with recovery_lock:
            if webview_completed.is_set():
                return

            webview_completed.set()
            # 失败必带可执行文件路径:缺 UI 资源这类错误只列相对路径时,
            # 无法区分「安装版缺文件」和「误运行了 dist 下的裸 exe」
            logger.error("Startup failed (exe=%s): %s", sys.executable, reason)

            if js_api:
                js_api.write_log("WARN", "WebView2", detail=reason, success=False)
                js_api.flush_logs_now()

            if (
                recover
                and js_api
                and restart_with_new_webview_profile(js_api.path_webview, __file__)
            ):
                os._exit(3)

            if not hide_on_start:
                show_startup_error(
                    f"PYAS could not initialize its interface.\n\n{reason}\n\n"
                    f"Executable: {sys.executable}\n"
                    f"Diagnostic log: {STARTUP_LOG_PATH or 'unavailable'}"
                )

            os._exit(3)

    try:
        wait_for_recovery_parent()
        arguments = os.environ.get("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "")
        # Chromium 会把「被遮挡/最小化」的窗口当成不可见并停掉渲染,还原后要过一两秒
        # 才重新合成 —— 实测录屏里是 1.6s 的空白(只剩背景和分隔线)。
        # 关掉遮挡计算与后台节流,窗口一还原就能立刻出画面。
        os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
            arguments + " --proxy-bypass-list=localhost;127.0.0.1"
            " --disable-features=CalculateNativeWinOcclusion"
            " --disable-backgrounding-occluded-windows"
        ).strip()
        frontend_errors = get_frontend_asset_errors()

        if frontend_errors:
            raise RuntimeError("UI files are incomplete: " + "; ".join(frontend_errors))

        logger.info("UI assets verified")

        stage = "http"
        port_container, server_errors = [], []
        server_ready = threading.Event()
        threading.Thread(
            target=start_api, args=(port_container, server_errors, server_ready), daemon=True
        ).start()

        if not server_ready.wait(5.0) or not port_container or server_errors:
            raise RuntimeError("Local UI server did not start: " + "; ".join(server_errors))

        verify_ui_server(port_container[0])

        stage = "api"
        logger.info("Initializing Python API")
        js_api = WindowAPI()

        # 发起进程溯源的启动/状态已并入 init_engine_thread(PYAS_ETW.EtwMixin),
        # 这里不再做只探测不启动的空记录 —— 旧 _attribution_status 无人消费。
        js_api.file_webview_log = STARTUP_LOG_PATH or js_api.file_webview_log

        stage = "profile"
        preferred_profile = os.environ.get("PYAS_WEBVIEW_PROFILE", js_api.path_webview)
        js_api.path_webview = prepare_webview_profile(preferred_profile)

        stage = "runtime"
        check_webview_dependencies(webview)

        stage = "window"
        user32 = ctypes.windll.user32
        pos_x = (user32.GetSystemMetrics(0) - init_width) // 2
        pos_y = (user32.GetSystemMetrics(1) - init_height) // 2
        startup_url = f"http://127.0.0.1:{port_container[0]}/"
        # 原生窗口底色跟随已保存主题,消除深色主题启动时的闪白
        window_background = window_background_for(
            getattr(js_api, "pyas_config", {}).get("theme", "system_switch")
        )
        window = webview.create_window(
            title=PYAS_WINDOW_TITLE,
            url=startup_url,
            width=init_width,
            height=init_height,
            x=pos_x,
            y=pos_y,
            frameless=True,
            easy_drag=False,
            js_api=js_api,
            background_color=window_background,
            hidden=hide_on_start,
        )

        if platform.system() == "Windows":
            window_hook = WindowHook(PYAS_WINDOW_TITLE, js_api)
            window.events.shown += window_hook.hook

        js_api.set_window(window)
        logger.info("Native window configured; hidden=%s", hide_on_start)

        stage = "tray"
        js_api.show_tray()
        logger.info("Tray initialized")
        webview_loaded_event = threading.Event()
        dnd_state = {"bound": False}

        def bind_dnd():
            webview_loaded_event.set()
            logger.info("WebView document loaded")

            if dnd_state["bound"]:
                return

            try:
                window.dom.document.events.drop += DOMEventHandler(js_api.on_drop, True, True)
                dnd_state["bound"] = True
            except Exception:
                logger.exception("Drag and drop binding failed")

        def webview_startup_watchdog():
            if js_api.ui_ready_event.wait(30.0) or webview_completed.is_set():
                return

            if webview_loaded_event.is_set():
                logger.warning("UI bridge timeout; reloading once")

                try:
                    window.load_url(startup_url)
                except Exception:
                    logger.exception("UI reload failed")

            if js_api.ui_ready_event.wait(30.0) or webview_completed.is_set():
                return

            reason = (
                "Python bridge or configuration initialization timed out"
                if webview_loaded_event.is_set()
                else ("WebView2 did not load the local UI document")
            )
            fail_startup(reason, recover=True)

        def on_closed():
            webview_completed.set()

        window.events.loaded += bind_dnd
        window.events.closed += on_closed
        threading.Thread(target=webview_startup_watchdog, daemon=True).start()
        stage = "webview"
        logger.info("Starting edgechromium")
        webview.start(gui="edgechromium", private_mode=False, storage_path=js_api.path_webview)
        webview_completed.set()
    except Exception as e:
        logger.exception("Startup exception at stage=%s", stage)
        fail_startup(f"{stage}: {e}", recover=stage == "webview")


if __name__ == "__main__":
    if "-quit" in sys.argv or "-driver-unload" in sys.argv or "-driver-uninstall" in sys.argv:
        controller = WindowAPI()

        if "-quit" in sys.argv or "-driver-uninstall" in sys.argv:
            success, delete_error = controller.uninstall_system_driver()

            if not success:
                controller.write_log(
                    "WARN",
                    "Driver Service",
                    detail=f"DeleteService failed: 0x{delete_error & 0xFFFFFFFF:08X}",
                    success=False,
                )
        else:
            success = controller.stop_system_driver()

        controller.flush_logs_now()
        os._exit(0 if success else 2)

    start_ui()
