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
from PYAS_Logs import LogMixin
from PYAS_Runtime import RuntimeMixin
from PYAS_AI import AIMixin


class _MainMixin(WindowsMixin, ConfigMixin, LogMixin, RuntimeMixin, AIMixin):
    def __init__(self):
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
                lambda item: self.get_tray_text("open_ui"), self.restore_from_tray, default=True
            ),
            pystray.MenuItem(lambda item: self.get_tray_text("optimize_mem"), self.optimize_memory),
            pystray.MenuItem(
                lambda item: self.get_tray_text("check_update"), self.tray_check_update
            ),
            pystray.MenuItem(lambda item: self.get_tray_text("exit_app"), self.close),
        )
        self.tray_icon = pystray.Icon("PYAS", self.get_app_icon(), "PYAS Security Cyanmod", menu)
        self.tray_icon.run_detached()

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

    def restore_from_tray(self, icon=None, item=None):
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
        if self._window:
            self._window.minimize()
        else:
            hwnd = self._find_main_hwnd()

            if hwnd:
                self.user32.ShowWindow(hwnd, 6)

    def hide_window(self):
        if self._window:
            self._window.hide()

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

        with self.lock_file_ops:
            if getattr(self, "h_dir_file", None):
                try:
                    self.kernel32.CloseHandle(self.h_dir_file)
                except Exception:
                    log_exception("PYAS._MainMixin.close:380")
                    pass

                self.h_dir_file = None

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
            self.write_log('INFO' if result.returncode == 0 else 'WARN', 'Modern Context Menu',
                detail=detail,
                success=result.returncode == 0)
            return remember(result.returncode == 0, detail if result.returncode else '')
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
        self.SC_MAXIMIZE = 0xF030
        self.SC_RESTORE = 0xF120
        self.HTCAPTION = 2
        self.MIN_WINDOW_WIDTH = 720
        self.MIN_WINDOW_HEIGHT = 560
        self.GWLP_WNDPROC = -4

        self.RECT = RECT
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

    def call_default(self, hwnd, msg, wparam, lparam):
        if self.old_wndproc:
            return self.user32.CallWindowProcW(self.old_wndproc, hwnd, msg, wparam, lparam)

        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def wndproc(self, hwnd, msg, wparam, lparam):
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

            if sc_value in (self.SC_MAXIMIZE, self.SC_RESTORE):
                self.api_ref._maximized = sc_value == self.SC_MAXIMIZE
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
            logger.error("Startup failed: %s", reason)

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
                    f"Diagnostic log: {STARTUP_LOG_PATH or 'unavailable'}"
                )

            os._exit(3)

    try:
        wait_for_recovery_parent()
        arguments = os.environ.get("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "")
        os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
            arguments + " --proxy-bypass-list=localhost;127.0.0.1"
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
