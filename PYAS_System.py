from PYAS_Diagnostics import log_exception
import os
import sys
import time
import shutil
import winreg
import subprocess
import ctypes
import ctypes.wintypes
from PYAS_WinAPI import (

    FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    INTERNAL_STORAGE_BUS_TYPES,
    INVALID_HANDLE_VALUE,
    IOCTL_STORAGE_GET_HOTPLUG_INFO,
    IOCTL_STORAGE_QUERY_PROPERTY,
    OPEN_EXISTING,
    PROPERTY_STANDARD_QUERY,
    STORAGE_DESCRIPTOR_HEADER,
    STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_DEVICE_PROPERTY,
    STORAGE_HOTPLUG_INFO,
    STORAGE_PROPERTY_QUERY,
)

from PYAS_LogTexts import LOG_TEXTS as _LT


class SystemMixin:
    def _is_internal_physical_drive(self, drive):
        drive_path = rf"\\.\PhysicalDrive{drive}"
        handle = self.kernel32.CreateFileW(
            drive_path,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )

        if handle in (None, INVALID_HANDLE_VALUE):
            return False

        try:
            query = STORAGE_PROPERTY_QUERY(STORAGE_DEVICE_PROPERTY, PROPERTY_STANDARD_QUERY)
            header = STORAGE_DESCRIPTOR_HEADER()
            bytes_returned = ctypes.wintypes.DWORD(0)

            if not self.kernel32.DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                ctypes.byref(query),
                ctypes.sizeof(query),
                ctypes.byref(header),
                ctypes.sizeof(header),
                ctypes.byref(bytes_returned),
                None,
            ):
                return False

            minimum_size = STORAGE_DEVICE_DESCRIPTOR.BusType.offset + ctypes.sizeof(ctypes.c_int)

            if (
                bytes_returned.value < ctypes.sizeof(header)
                or header.Size < minimum_size
                or header.Size > 65536
            ):
                return False

            descriptor_buffer = ctypes.create_string_buffer(header.Size)
            bytes_returned.value = 0

            if not self.kernel32.DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                ctypes.byref(query),
                ctypes.sizeof(query),
                descriptor_buffer,
                ctypes.sizeof(descriptor_buffer),
                ctypes.byref(bytes_returned),
                None,
            ):
                return False

            descriptor = ctypes.cast(
                descriptor_buffer, ctypes.POINTER(STORAGE_DEVICE_DESCRIPTOR)
            ).contents

            if (
                bytes_returned.value < minimum_size
                or descriptor.RemovableMedia
                or descriptor.BusType not in INTERNAL_STORAGE_BUS_TYPES
            ):
                return False

            hotplug = STORAGE_HOTPLUG_INFO()
            hotplug.Size = ctypes.sizeof(hotplug)
            bytes_returned.value = 0

            if not self.kernel32.DeviceIoControl(
                handle,
                IOCTL_STORAGE_GET_HOTPLUG_INFO,
                None,
                0,
                ctypes.byref(hotplug),
                ctypes.sizeof(hotplug),
                ctypes.byref(bytes_returned),
                None,
            ):
                return False

            if bytes_returned.value < ctypes.sizeof(hotplug):
                return False

            return not (hotplug.MediaRemovable or hotplug.MediaHotplug or hotplug.DeviceHotplug)
        except Exception:
            log_exception("PYAS_System.SystemMixin._is_internal_physical_drive:80")
            return False
        finally:
            self.kernel32.CloseHandle(handle)

    def backup_mbr(self, max_drives=26):
        self.mbr_backup = {}

        for drive in range(max_drives):
            if not self._is_internal_physical_drive(drive):
                continue

            try:
                with open(rf"\\.\PhysicalDrive{drive}", "rb") as f:
                    mbr = f.read(512)

                    if len(mbr) == 512 and mbr[510:512] == b"\x55\xAA":
                        self.mbr_backup[drive] = mbr

            except Exception:
                log_exception("PYAS_System.SystemMixin.backup_mbr:97")
                continue

    def _log_repair_failure(self, action, error):
        # 修复循环每 0.5 秒重试一次;持续失败(如 ACL 保护的键)只在错误内容
        # 变化时记一条 WARN,避免提权与普通权限两种状态下都刷屏
        detail = str(error)
        cache = getattr(self, "_repair_failure_cache", None)

        if cache is None:
            cache = self._repair_failure_cache = {}

        if cache.get(action) != detail:
            cache[action] = detail
            self.write_log("WARN", action, detail=detail, success=False)

    def check_system_mbr(self):
        for drive, mbr_value in list(self.mbr_backup.items()):
            try:
                with open(rf"\\.\PhysicalDrive{drive}", "rb") as f:
                    if f.read(512) != mbr_value:
                        return True

            except Exception:
                log_exception("PYAS_System.SystemMixin.check_system_mbr:107")
                pass

        return False

    def repair_system_mbr(self):
        for drive, mbr_value in list(self.mbr_backup.items()):
            drive_path = rf"\\.\PhysicalDrive{drive}"

            try:
                with open(drive_path, "rb+") as f:
                    if f.read(512) != mbr_value:
                        f.seek(0)
                        f.write(mbr_value)
                        self.write_log("INFO", "MBR Repaired", source=drive_path, operate=True)

            except Exception:
                log_exception("PYAS_System.SystemMixin.repair_system_mbr:120")
                pass

    def _get_restrict_lists(self):
        permissions = [
            "NoControlPanel",
            "NoDrives",
            "NoFileMenu",
            "NoFind",
            "NoStartMenuPinnedList",
            "NoSetFolders",
            "NoSetFolderOptions",
            "NoViewOnDrive",
            "NoClose",
            "NoDesktop",
            "NoLogoff",
            "NoFolderOptions",
            "RestrictRun",
            "NoViewContextMenu",
            "HideClock",
            "NoStartMenuMyGames",
            "NoStartMenuMyMusic",
            "DisableCMD",
            "NoAddingComponents",
            "NoWinKeys",
            "NoStartMenuLogOff",
            "NoSimpleNetIDList",
            "NoLowDiskSpaceChecks",
            "DisableLockWorkstation",
            "Restrict_Run",
            "DisableTaskMgr",
            "DisableRegistryTools",
            "DisableChangePassword",
            "Wallpaper",
            "NoComponents",
            "NoStartMenuMorePrograms",
            "NoActiveDesktop",
            "NoSetActiveDesktop",
            "NoRecentDocsMenu",
            "NoWindowsUpdate",
            "NoChangeStartMenu",
            "NoFavoritesMenu",
            "NoRecentDocsHistory",
            "NoSetTaskbar",
            "NoSMHelp",
            "NoTrayContextMenu",
            "NoManageMyComputerVerb",
            "NoRealMode",
            "NoRun",
            "ClearRecentDocsOnExit",
            "NoActiveDesktopChanges",
            "NoStartMenuNetworkPlaces",
        ]
        paths = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\MMC"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Windows\System"),
            (
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            ),
            (
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            ),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System"),
        ]
        return permissions, paths

    def check_system_restrict(self):
        permissions, paths = self._get_restrict_lists()

        for hkey, path in paths:
            for val in permissions:
                if self._reg_read(hkey, path, val) is not None:
                    return True

        return False

    def check_system_file_type(self):
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for ext in [".exe", ".bat", ".cmd", ".com"]:
                if self._reg_read(root, rf"SOFTWARE\Classes\{ext}", "") != (
                    "exefile" if ext == ".exe" else ext[1:] + "file"
                ):
                    return True

            for cmd in ["open", "runas"]:
                if (
                    self._reg_read(root, rf"SOFTWARE\Classes\exefile\shell\{cmd}\command", "")
                    != '"%1" %*'
                ):
                    return True

        return False

    def check_system_file_icon(self):
        return any(
            self._reg_read(root, r"SOFTWARE\Classes\exefile\DefaultIcon", "") != "%1"
            for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
        )

    def check_system_image(self):
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                0,
                winreg.KEY_READ,
            ) as reg:
                i = 0

                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)

                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_READ) as sub_reg:
                            for val in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.QueryValueEx(sub_reg, val)
                                    return True

                                except FileNotFoundError:
                                    pass

                        i += 1
                    except OSError:
                        log_exception("PYAS_System.SystemMixin.check_system_image:185")
                        break

        except Exception:
            log_exception("PYAS_System.SystemMixin.check_system_image:188")
            pass

        return False

    def check_system_wallpaper(self):
        return self._reg_read(
            winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "Wallpaper"
        ) != os.path.join(self.path_system, "web", "wallpaper", "Windows", "img0.jpg")

    def scan_system_repair(self):
        items = []

        for drive, mbr_value in list(self.mbr_backup.items()):
            drive_path = rf"\\.\PhysicalDrive{drive}"

            try:
                with open(drive_path, "rb") as f:
                    if f.read(512) != mbr_value:
                        items.append(
                            {"id": f"mbr|{drive}", "display": "repair_mbr", "path": drive_path}
                        )

            except Exception:
                log_exception("PYAS_System.SystemMixin.scan_system_repair:205")
                pass

        permissions, paths = self._get_restrict_lists()

        for hkey, path in paths:
            for val in permissions:

                if self._reg_read(hkey, path, val) is not None:
                    root = "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                    items.append(
                        {
                            "id": f"restrict|{root}\\{path}\\{val}",
                            "display": "repair_limit",
                            "path": rf"{root}\{path}\{val}",
                        }
                    )

        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            root_str = "HKLM" if root == winreg.HKEY_LOCAL_MACHINE else "HKCU"

            for ext in [".exe", ".bat", ".cmd", ".com"]:
                expected = "exefile" if ext == ".exe" else ext[1:] + "file"

                if self._reg_read(root, rf"SOFTWARE\Classes\{ext}", "") != expected:
                    items.append(
                        {
                            "id": f"file_type|{root_str}\\{ext}",
                            "display": "repair_assoc",
                            "path": rf"{root_str}\SOFTWARE\Classes\{ext}",
                        }
                    )

            for cmd in ["open", "runas"]:
                if (
                    self._reg_read(root, rf"SOFTWARE\Classes\exefile\shell\{cmd}\command", "")
                    != '"%1" %*'
                ):
                    items.append(
                        {
                            "id": f"file_type|{root_str}\\exefile\\{cmd}",
                            "display": "repair_assoc",
                            "path": rf"{root_str}\SOFTWARE\Classes\exefile\shell\{cmd}\command",
                        }
                    )

            if self._reg_read(root, r"SOFTWARE\Classes\exefile\DefaultIcon", "") != "%1":
                items.append(
                    {
                        "id": f"file_icon|{root_str}",
                        "display": "repair_icon",
                        "path": rf"{root_str}\SOFTWARE\Classes\exefile\DefaultIcon",
                    }
                )

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                0,
                winreg.KEY_READ,
            ) as reg:
                i = 0

                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)

                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_READ) as sub_reg:
                            for val in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.QueryValueEx(sub_reg, val)
                                    items.append(
                                        {
                                            "id": f"image|{subkey}",
                                            "display": "repair_hijack",
                                            "path": rf"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{subkey}",
                                        }
                                    )
                                    break
                                except FileNotFoundError:
                                    pass

                        i += 1
                    except OSError:
                        log_exception("PYAS_System.SystemMixin.scan_system_repair:247")
                        break

        except Exception:
            log_exception("PYAS_System.SystemMixin.scan_system_repair:250")
            pass

        wp = self._reg_read(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "Wallpaper")
        expected_wp = os.path.join(self.path_system, "web", "wallpaper", "Windows", "img0.jpg")

        if wp != expected_wp:
            items.append(
                {
                    "id": "wallpaper|0",
                    "display": "repair_wallpaper",
                    "path": wp if wp else r"HKCU\Control Panel\Desktop\Wallpaper",
                }
            )

        return items

    def repair_system_restrict(self):
        permissions, paths = self._get_restrict_lists()

        for hkey, path in paths:
            for val in permissions:
                self._reg_delete(hkey, path, val)

    def repair_system_file_type(self):
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for ext in [".exe", ".bat", ".cmd", ".com"]:
                self._reg_write(
                    root,
                    rf"SOFTWARE\Classes\{ext}",
                    None,
                    winreg.REG_SZ,
                    "exefile" if ext == ".exe" else ext[1:] + "file",
                )

            for cmd in ["open", "runas"]:
                self._reg_write(
                    root,
                    rf"SOFTWARE\Classes\exefile\shell\{cmd}\command",
                    None,
                    winreg.REG_SZ,
                    '"%1" %*',
                )

    def repair_system_file_icon(self):
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            self._reg_write(
                root, r"SOFTWARE\Classes\exefile\DefaultIcon", None, winreg.REG_SZ, "%1"
            )

    def repair_system_image(self):
        # IFEO 修复需要 HKLM 写权限;普通权限下静默跳过(用户手动触发的路径)
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                0,
                winreg.KEY_ALL_ACCESS,
            ) as reg:
                i = 0

                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)
                    except OSError as error:
                        # 枚举到末尾抛 259(ERROR_NO_MORE_ITEMS),属正常结束,不记异常
                        if getattr(error, "winerror", None) != 259:
                            log_exception("PYAS_System.SystemMixin.repair_system_image:292")
                        break

                    i += 1

                    try:
                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_ALL_ACCESS) as sub_reg:
                            for val in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.DeleteValue(sub_reg, val)
                                except FileNotFoundError:
                                    pass
                    except OSError:
                        # TrustedInstaller 拥有的子键即使管理员也无权打开:
                        # 跳过该键继续。旧逻辑在此中止整个枚举,每个周期都在
                        # 同一位置失败,同一条异常在日志里刷了两万多条
                        continue

        except Exception as e:
            log_exception("PYAS_System.SystemMixin.repair_system_image:295")
            self._log_repair_failure("repair_system_image", e)

    def repair_system_wallpaper(self):
        try:
            wallpaper = os.path.join(self.path_system, "web", "wallpaper", "Windows", "img0.jpg")

            if not os.path.exists(wallpaper):
                return

            self._reg_write(
                winreg.HKEY_CURRENT_USER,
                r"Control Panel\Desktop",
                "Wallpaper",
                winreg.REG_SZ,
                wallpaper,
            )
            theme_dir = os.path.join(self.path_appdata, "Microsoft", "Windows", "Themes")

            for fname in ["TranscodedWallpaper", "TranscodedWallpaper.tmp"]:
                try:
                    os.remove(os.path.join(theme_dir, fname))
                except Exception:
                    log_exception("PYAS_System.SystemMixin.repair_system_wallpaper:310")
                    pass

            shutil.rmtree(os.path.join(theme_dir, "CachedFiles"), ignore_errors=True)
            self.user32.SystemParametersInfoW(20, 0, wallpaper, 3)

        except Exception as e:
            log_exception("PYAS_System.SystemMixin.repair_system_wallpaper:316")
            self._log_repair_failure("repair_system_wallpaper", e)

    def execute_system_repair(self, items):
        try:
            types = set(item.split("|")[0] for item in items)

            if "mbr" in types:
                self.repair_system_mbr()

            if "restrict" in types:
                self.repair_system_restrict()

            if "file_type" in types:
                self.repair_system_file_type()

            if "file_icon" in types:
                self.repair_system_file_icon()

            if "image" in types:
                self.repair_system_image()

            if "wallpaper" in types:
                self.repair_system_wallpaper()

            self.write_log(
                "INFO", "System Repair", detail=self._loc(_LT["repair_done"]).format(len(items)), operate=True
            )
            return True

        except Exception as e:
            log_exception("PYAS_System.SystemMixin.execute_system_repair:339")
            self.write_log(
                "WARN", "execute_system_repair", detail=str(e), operate=True, success=False
            )
            return False

    def protect_system_thread(self):
        while True:
            with self.lock_config:
                if not self.pyas_config.get("system_switch", False):
                    break

            try:
                # IFEO/注册表修复均需 HKLM 写权限;普通权限下跳过修复,
                # 只保留进程守护,避免保护线程每 0.5 秒刷一遍拒绝访问日志
                if ctypes.windll.shell32.IsUserAnAdmin():
                    self.repair_system_mbr()
                    self.repair_system_restrict()
                    self.repair_system_file_type()
                    self.repair_system_file_icon()
                    self.repair_system_image()
                self.check_process_survival()
                time.sleep(0.5)

            except Exception as e:
                log_exception("PYAS_System.SystemMixin.protect_system_thread:357")
                self._log_repair_failure("protect_system_thread", e)

    def check_process_survival(self):
        try:
            running = any(
                exe_name.lower() == "explorer.exe" for _, exe_name in self._enum_processes()
            )

            if not running:
                explorer = self._find_windows_tool("explorer.exe")

                if not explorer:
                    return

                subprocess.Popen([explorer])
                self.write_log("INFO", "System Restart", source="explorer.exe")

        except Exception:
            log_exception("PYAS_System.SystemMixin.check_process_survival:371")
            pass

    def check_notification_permission(self):
        result = {
            "supported": False,
            "enabled": True,
            "global_enabled": True,
            "app_enabled": True,
            "detail": "",
        }

        try:
            if sys.getwindowsversion().major < 10:
                result["detail"] = "windows below 10 has no notification settings"
                return result

            result["supported"] = True
            global_enabled = True

            try:
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\PushNotifications",
                    0,
                    winreg.KEY_READ,
                ) as key:
                    value, _ = winreg.QueryValueEx(key, "ToastEnabled")

                    if int(value) == 0:
                        global_enabled = False

            except FileNotFoundError:
                pass

            if global_enabled:
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER,
                        r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
                        0,
                        winreg.KEY_READ,
                    ) as key:
                        value, _ = winreg.QueryValueEx(key, "NOC_GLOBAL_SETTING_TOASTS_ENABLED")

                        if int(value) == 0:
                            global_enabled = False

                except FileNotFoundError:
                    pass

            app_enabled = True
            exe_path = os.path.normcase(os.path.normpath(self.file_pyas))
            exe_name = os.path.basename(exe_path)
            settings_path = r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"

            try:
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, settings_path, 0, winreg.KEY_READ
                ) as key:
                    index = 0

                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, index)
                        except OSError:
                            break

                        index += 1
                        normalized = os.path.normcase(subkey_name)

                        if normalized != exe_path and not normalized.endswith("\\" + exe_name):
                            continue

                        try:
                            with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ) as subkey:
                                value, _ = winreg.QueryValueEx(subkey, "Enabled")

                                if int(value) == 0:
                                    app_enabled = False
                                    break

                        except FileNotFoundError:
                            continue

            except FileNotFoundError:
                pass

            result["global_enabled"] = global_enabled
            result["app_enabled"] = app_enabled
            result["enabled"] = global_enabled and app_enabled

        except Exception as error:
            log_exception("PYAS_System.SystemMixin.check_notification_permission")
            result["detail"] = str(error)

        return result

    def open_notification_settings(self):
        try:
            os.startfile("ms-settings:notifications")
            return True
        except Exception as error:
            log_exception("PYAS_System.SystemMixin.open_notification_settings")
            self.write_log("WARN", "open_notification_settings", detail=str(error), success=False)
            return False
