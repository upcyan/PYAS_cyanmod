from PYAS_Diagnostics import log_exception
import os
import re
import io
import csv
import json
import time
import shutil
import threading
import sys
import pefile
import hashlib
import winreg
import requests
import subprocess
import ctypes
import ctypes.wintypes
from PYAS_Version import VERSION
from concurrent.futures import ThreadPoolExecutor
from PYAS_WinAPI import (
    COPYDATASTRUCT,
    ERROR_LOCK_VIOLATION,
    ERROR_NOT_FOUND,
    ERROR_OPERATION_ABORTED,
    ERROR_SHARING_VIOLATION,
    FILE_ATTRIBUTE_NORMAL,
    FILE_LOCK_RETRY_SECONDS,
    FILE_NOTIFY_INFORMATION,
    FILE_SCAN_DEBOUNCE_SECONDS,
    FILE_SCAN_RETRY_SECONDS,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILTER_MESSAGE_HEADER,
    FLT_PORT_FLAG_SYNC_HANDLE,
    GENERIC_READ,
    GUID,
    HRESULT_IO_PENDING,
    INTERNAL_STORAGE_BUS_TYPES,
    INVALID_HANDLE_VALUE,
    IOCTL_STORAGE_GET_HOTPLUG_INFO,
    IOCTL_STORAGE_QUERY_PROPERTY,
    IO_COUNTERS,
    LUID,
    LUID_AND_ATTRIBUTES,
    MEMORY_BASIC_INFORMATION,
    MIB_TCPROW_OWNER_PID,
    OPEN_EXISTING,
    OVERLAPPED,
    POINT,
    PROCESSENTRY32W,
    PROCESS_BASIC_INFORMATION,
    PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SUSPEND_RESUME,
    PROCESS_TERMINATE,
    PROCESS_VM_READ,
    PROPERTY_STANDARD_QUERY,
    PYAS_CONNECTION_CONTEXT,
    PYAS_CONNECTION_MAGIC,
    PYAS_CONNECTION_VERSION,
    PYAS_FULL_MESSAGE,
    PYAS_MESSAGE,
    PYAS_PROCESS_NETWORK_ACCESS,
    PYAS_PROCESS_SCAN_ACCESS,
    PYAS_PROCESS_TERMINATE_ACCESS,
    PYAS_USER_MESSAGE,
    RECT,
    SERVICE_STATUS_PROCESS,
    SHQUERYRBINFO,
    STORAGE_DESCRIPTOR_HEADER,
    STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_DEVICE_PROPERTY,
    STORAGE_HOTPLUG_INFO,
    STORAGE_PROPERTY_QUERY,
    TOKEN_PRIVILEGES,
    UNICODE_STRING,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    WINTRUST_DATA,
    WINTRUST_DATA_UNION,
    WINTRUST_FILE_INFO,
)
from PYAS_Autostart import AutostartMixin
from PYAS_Process import ProcessMixin
from PYAS_Maintenance import MaintenanceMixin
from PYAS_Threats import ThreatMixin


class ToolsMixin(AutostartMixin, ProcessMixin, MaintenanceMixin, ThreatMixin):
    def _find_windows_tool(self, *names):
        windows_dir = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
        search_dirs = [
            os.path.join(windows_dir, "Sysnative"),
            os.path.join(windows_dir, "System32"),
            windows_dir,
        ]

        for name in names:
            executable_name = name if name.lower().endswith(".exe") else name + ".exe"

            for directory in search_dirs:
                candidate = os.path.join(directory, executable_name)

                if os.path.isfile(candidate):
                    return candidate

            candidate = shutil.which(name)

            if candidate:
                return candidate

        return None

    def _run_windows_tool(self, tool_names, arguments, **kwargs):
        executable = self._find_windows_tool(*tool_names)

        if not executable:
            return None

        options = {"creationflags": 0x08000000}
        options.update(kwargs)

        try:
            return subprocess.run([executable, *arguments], **options)
        except (FileNotFoundError, OSError):
            log_exception("PYAS_Tools.ToolsMixin._run_windows_tool:43")
            return None

    def _run_powershell(self, command, **kwargs):
        return self._run_windows_tool(
            (r"WindowsPowerShell\v1.0\powershell.exe", "powershell.exe", "pwsh.exe"),
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-WindowStyle",
                "Hidden",
                "-Command",
                command,
            ],
            **kwargs,
        )

    def _clear_event_log(self, log_name):
        result = self._run_windows_tool(
            ("wevtutil.exe",),
            ["cl", log_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if result is not None and result.returncode == 0:
            return True

        try:
            wevtapi = ctypes.WinDLL("wevtapi", use_last_error=True)
            wevtapi.EvtClearLog.argtypes = [
                ctypes.wintypes.HANDLE,
                ctypes.wintypes.LPCWSTR,
                ctypes.wintypes.LPCWSTR,
                ctypes.wintypes.DWORD,
            ]
            wevtapi.EvtClearLog.restype = ctypes.wintypes.BOOL
            return bool(wevtapi.EvtClearLog(None, log_name, None, 0))

        except Exception:
            log_exception("PYAS_Tools.ToolsMixin._clear_event_log:69")
            return False

    def _manage_service_native(self, service_name, action):
        SC_MANAGER_CONNECT = 0x0001
        SERVICE_CHANGE_CONFIG = 0x0002
        DELETE = 0x00010000
        SERVICE_NO_CHANGE = 0xFFFFFFFF
        SERVICE_AUTO_START = 0x00000002
        SERVICE_DISABLED = 0x00000004

        try:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            advapi32.OpenSCManagerW.argtypes = [
                ctypes.wintypes.LPCWSTR,
                ctypes.wintypes.LPCWSTR,
                ctypes.wintypes.DWORD,
            ]
            advapi32.OpenSCManagerW.restype = ctypes.wintypes.HANDLE
            advapi32.OpenServiceW.argtypes = [
                ctypes.wintypes.HANDLE,
                ctypes.wintypes.LPCWSTR,
                ctypes.wintypes.DWORD,
            ]
            advapi32.OpenServiceW.restype = ctypes.wintypes.HANDLE
            advapi32.CloseServiceHandle.argtypes = [ctypes.wintypes.HANDLE]
            advapi32.CloseServiceHandle.restype = ctypes.wintypes.BOOL

            manager = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)

            if not manager:
                return False

            service = None

            try:
                desired_access = DELETE if action == "delete" else SERVICE_CHANGE_CONFIG
                service = advapi32.OpenServiceW(manager, service_name, desired_access)

                if not service:
                    return False

                if action == "delete":
                    advapi32.DeleteService.argtypes = [ctypes.wintypes.HANDLE]
                    advapi32.DeleteService.restype = ctypes.wintypes.BOOL
                    return bool(advapi32.DeleteService(service))

                start_type = SERVICE_AUTO_START if action == "enable" else SERVICE_DISABLED
                advapi32.ChangeServiceConfigW.argtypes = [
                    ctypes.wintypes.HANDLE,
                    ctypes.wintypes.DWORD,
                    ctypes.wintypes.DWORD,
                    ctypes.wintypes.DWORD,
                    ctypes.wintypes.LPCWSTR,
                    ctypes.wintypes.LPCWSTR,
                    ctypes.POINTER(ctypes.wintypes.DWORD),
                    ctypes.wintypes.LPCWSTR,
                    ctypes.wintypes.LPCWSTR,
                    ctypes.wintypes.LPCWSTR,
                    ctypes.wintypes.LPCWSTR,
                ]
                advapi32.ChangeServiceConfigW.restype = ctypes.wintypes.BOOL
                return bool(
                    advapi32.ChangeServiceConfigW(
                        service,
                        SERVICE_NO_CHANGE,
                        start_type,
                        SERVICE_NO_CHANGE,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                )
            finally:
                if service:
                    advapi32.CloseServiceHandle(service)

                advapi32.CloseServiceHandle(manager)
        except Exception:
            log_exception("PYAS_Tools.ToolsMixin._manage_service_native:137")
            return False

    def _manage_scheduled_task(self, task_path, action):
        schtasks_action = "/delete" if action == "delete" else "/change"
        arguments = [schtasks_action, "/tn", task_path]

        if action == "delete":
            arguments.append("/f")
        else:
            arguments.append("/enable" if action == "enable" else "/disable")

        result = self._run_windows_tool(
            ("schtasks.exe",), arguments, capture_output=True, text=True
        )

        if result is not None and result.returncode == 0:
            return True

        escaped_path = task_path.replace("'", "''")
        operation = {
            "delete": "Unregister-ScheduledTask -InputObject $Task -Confirm:$false",
            "enable": "Enable-ScheduledTask -InputObject $Task | Out-Null",
            "disable": "Disable-ScheduledTask -InputObject $Task | Out-Null",
        }.get(action)

        if not operation:
            return False

        command = (
            f"$FullName = '{escaped_path}'; "
            "$Task = Get-ScheduledTask -ErrorAction SilentlyContinue | "
            "Where-Object { ($_.TaskPath + $_.TaskName) -eq $FullName } | Select-Object -First 1; "
            f"if ($Task) {{ {operation} }} else {{ exit 1 }}"
        )
        result = self._run_powershell(command, capture_output=True, text=True)
        return bool(result and result.returncode == 0)

    def _reg_read(self, root, path, value_name):
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as reg:
                val, _ = winreg.QueryValueEx(reg, value_name)
                return val

        except Exception:
            log_exception("PYAS_Tools.ToolsMixin._reg_read:181")
            return None

    def _reg_write(self, root, path, value_name, value_type, value):
        try:
            with winreg.CreateKey(root, path) as reg:
                if value_name is None:
                    winreg.SetValue(reg, "", value_type, value)
                else:
                    winreg.SetValueEx(reg, value_name, 0, value_type, value)

                actual, actual_type = winreg.QueryValueEx(reg, value_name or "")
                return actual == value and actual_type == value_type
        except Exception:
            log_exception("ToolsMixin._reg_write")
            return False

    def _reg_delete(self, root, path, value_name=None):
        try:
            if value_name is None:
                winreg.DeleteKey(root, path)
            else:
                with winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WRITE) as reg:
                    winreg.DeleteValue(reg, value_name)

            return True
        except Exception:
            log_exception("PYAS_Tools.ToolsMixin._reg_delete:205")
            return False

    def start_daemon_thread(self, target, *args, **kwargs):
        t = threading.Thread(
            target=target,
            args=args,
            kwargs=kwargs,
            daemon=True,
            name=f"PYAS.{getattr(target, '__name__', 'worker')}",
        )
        t.start()
        return t

    def norm_path(self, path, must_exist=True):
        if isinstance(path, list):
            return [p for p in (self.norm_path(x, must_exist) for x in path) if p]

        if isinstance(path, str):
            try:
                ap = os.path.normpath(os.path.abspath(path))
                return ap if (not must_exist or os.path.exists(ap)) else None

            except Exception:
                log_exception("PYAS_Tools.ToolsMixin.norm_path:223")
                return None

        return path

    def path_equal(self, a, b):
        pa, pb = self.norm_path(a, must_exist=False), self.norm_path(b, must_exist=False)
        return os.path.normcase(pa) == os.path.normcase(pb) if pa and pb else False

    def get_file_version(self, file_path):
        pe = None

        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )

            for file_info in getattr(pe, "FileInfo", []):
                for info in file_info:
                    if getattr(info, "name", "") in ("StringFileInfo", b"StringFileInfo"):
                        for table in getattr(info, "StringTable", []):
                            for key, value in table.entries.items():
                                key = (
                                    key.decode("utf-8", "ignore")
                                    if isinstance(key, bytes)
                                    else str(key)
                                )

                                if key == "FileVersion":
                                    value = (
                                        value.decode("utf-8", "ignore")
                                        if isinstance(value, bytes)
                                        else str(value)
                                    )
                                    return value.strip()
        except Exception:
            log_exception("PYAS_Tools.ToolsMixin.get_file_version:246")
            pass
        finally:
            if pe is not None:
                pe.close()

        return "0.0.0.0"

    def compare_versions(self, v1, v2):
        try:
            val1 = tuple(int(x) for x in re.findall(r"\d+", re.sub(r"^[vV]\s*", "", str(v1))))
            val2 = tuple(int(x) for x in re.findall(r"\d+", re.sub(r"^[vV]\s*", "", str(v2))))
            length = max(len(val1), len(val2))
            return val1 + (0,) * (length - len(val1)) >= val2 + (0,) * (length - len(val2))

        except Exception:
            log_exception("PYAS_Tools.ToolsMixin.compare_versions:259")
            return False

    GITHUB_RELEASE_HEADERS = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "PYAS-Cyanmod",
    }

    def _system_proxy_candidates(self):
        candidates = []

        for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            value = os.environ.get(key, "").strip()

            if value:
                candidates.append(value if "://" in value else "http://" + value)

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0,
                winreg.KEY_READ,
            ) as key:
                try:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")

                    if server and "=" not in server:
                        candidates.append("http://" + server)

                except FileNotFoundError:
                    pass

                try:
                    pac, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                    match = re.match(r"https?://([^/:]+):(\d+)", pac or "")

                    if match and match.group(1) in ("127.0.0.1", "localhost"):
                        candidates.append(f"http://127.0.0.1:{match.group(2)}")

                except FileNotFoundError:
                    pass

        except Exception:
            pass

        seen = set()
        unique = []

        for item in candidates:
            if item not in seen:
                seen.add(item)
                unique.append(item)

        return unique

    def _github_get(self, url, **kwargs):
        """GitHub 请求:先直连,失败后依次尝试系统代理(环境变量/注册表/PAC 端口)。"""
        kwargs.setdefault("timeout", 15)
        kwargs.setdefault("headers", self.GITHUB_RELEASE_HEADERS)

        try:
            response = requests.get(url, **kwargs)
            if response.status_code not in (502, 503, 504):
                return response
            response.close()

        except requests.RequestException:
            pass

        for proxy in self._system_proxy_candidates():
            try:
                return requests.get(url, proxies={"http": proxy, "https": proxy}, **kwargs)

            except requests.RequestException:
                continue

        return requests.get(url, **kwargs)

    def check_update(self):
        repository = 'upcyan/PYAS_cyanmod'
        try:
            current = VERSION
            # 不用 /releases/latest:连字符 tag(如 v3.7.1-1)会被 semver
            # 视为预发布而被 latest 端点跳过,列表取第一个非草稿更可靠
            response = self._github_get(f'https://api.github.com/repos/{repository}/releases?per_page=100')
            try:
                if response.status_code == 404:
                    return {'error': True, 'error_code': 'repository_unavailable', 'detail': repository}
                if response.status_code in (403, 429):
                    return {'error': True, 'error_code': 'rate_limited', 'detail': f'HTTP {response.status_code}'}
                response.raise_for_status()
                releases = response.json()
            finally:
                response.close()
            if not isinstance(releases, list):
                return {'error': True, 'error_code': 'invalid_response'}
            candidates = [r for r in releases if isinstance(r, dict) and not r.get('draft') and not r.get('prerelease')
                and re.fullmatch(r'[vV]?\d+(?:\.\d+){1,3}(?:-\d+)?', str(r.get('tag_name') or ''))]
            latest_release = max(candidates, key=lambda r: tuple(int(n) for n in re.findall(r'\d+', r['tag_name'])) +
                (0,) * (5 - len(re.findall(r'\d+', r['tag_name']))), default=None)

            if latest_release is None:
                return {'has_update': False, 'current': current, 'latest': current, 'no_release': True,
                    'url': f'https://github.com/{repository}/releases', 'asset': None}

            j = latest_release
            latest = str(j.get("tag_name") or j.get("name") or "").strip()
            page = j.get("html_url") or "https://github.com/upcyan/PYAS_cyanmod/releases"
            body = str(j.get("body") or "").strip()[:4000]
            published_at = str(j.get("published_at") or "")[:10]
            asset = None

            for item in j.get("assets") or []:
                name = str(item.get("name") or "")
                lower = name.lower()

                if lower.startswith('pyas_setup') and lower.endswith((".exe", ".msi")):
                    asset_url = str(item.get('browser_download_url') or '')
                    if not asset_url.startswith(f'https://github.com/{repository}/releases/download/'):
                        continue
                    asset = {
                        "name": name,
                        "url": item.get("browser_download_url"),
                        "size": int(item.get("size") or 0),
                        'digest': item.get('digest'),
                    }

                    if lower.endswith(".exe"):
                        break

            if latest:
                self._checked_update_asset = asset
                if not self.compare_versions(current, latest) and current != latest:
                    return {
                        "has_update": True,
                        "latest": latest,
                        "current": current,
                        "url": page,
                        "asset": asset,
                        "body": body,
                        "published_at": published_at,
                    }

                return {
                    "has_update": False,
                    "latest": latest,
                    "current": current,
                    "url": page,
                    "asset": asset,
                    "body": body,
                    "published_at": published_at,
                }

        except requests.RequestException as error:
            log_exception('PYAS_Tools.ToolsMixin.check_update.network')
            return {'error': True, 'error_code': 'network_error', 'detail': type(error).__name__}
        except Exception:
            log_exception("PYAS_Tools.ToolsMixin.check_update:274")
            pass

        return {"error": True, 'error_code': 'invalid_response'}

    def download_update(self, url, file_name=None):
        with self.lock_update:
            if getattr(self, "_update_downloading", False):
                # 重新发起视为继续:前端据此直接恢复进度显示
                return {"success": True, "already": True}

            if not isinstance(url, str) or not url.lower().startswith("https://github.com/"):
                return {"success": False, "error": "invalid download url"}
            asset = getattr(self, '_checked_update_asset', None)
            if not asset or url != asset.get('url') or file_name != asset.get('name'):
                return {'success': False, 'error': 'Check for updates again before downloading'}

            self._update_downloading = True
            self._update_download_state = {
                "downloading": True, "received": 0, "total": 0, "percent": -1,
            }

        threading.Thread(
            target=self._download_update_worker, args=(url, file_name), daemon=True
        ).start()
        return {"success": True, "started": True}

    def _download_update_worker(self, url, file_name):
        result = {"success": False, "path": None, "error": None, "size": 0}
        temp_path = None

        try:
            safe_name = os.path.basename(str(file_name) or url.rstrip("/").split("/")[-1])
            safe_name = safe_name.split("?")[0] or "PYAS_Setup.exe"

            if not safe_name.lower().endswith((".exe", ".msi")):
                safe_name += ".exe"

            downloads_dir = os.path.join(self.path_user, "Downloads")
            os.makedirs(downloads_dir, exist_ok=True)
            target_path = os.path.join(downloads_dir, safe_name)
            temp_path = target_path + ".part"
            response = self._github_get(url, stream=True)
            response.raise_for_status()
            total = int(response.headers.get("Content-Length") or 0)
            received = 0
            digest = hashlib.sha256()
            next_report = 0.0

            with open(temp_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue

                    f.write(chunk)
                    digest.update(chunk)
                    received += len(chunk)
                    now = time.time()

                    if now >= next_report:
                        next_report = now + 0.2
                        self._push_update_progress(received, total)

            response.close()
            expected = getattr(self, '_checked_update_asset', {}) or {}
            if expected.get('url') != url:
                raise ValueError('Update selection changed; check for updates again')
            if expected.get('size') and received != expected['size']:
                raise ValueError('Incomplete update download')
            expected_digest = expected.get('digest')
            if expected_digest and expected_digest != 'sha256:' + digest.hexdigest():
                raise ValueError('Update checksum mismatch')
            if temp_path:
                os.replace(temp_path, target_path)
                temp_path = None

            result = {"success": True, "path": target_path, "error": None, "size": received}
            self.write_log("INFO", "Update Download", detail=f"Saved {target_path}")

        except Exception as error:
            log_exception("PYAS_Tools.ToolsMixin.download_update")
            result = {"success": False, "path": None, "error": str(error), "size": 0}
            self.write_log("WARN", "Update Download", detail=str(error), success=False)

        finally:
            self._update_downloading = False
            self._update_download_state = {"downloading": False, "result": result}

            if temp_path:
                try:
                    os.remove(temp_path)
                except Exception:
                    log_exception("PYAS_Tools.ToolsMixin.download_update.cleanup")
                    pass

            self._emit_ui_js(
                f"if(window.updateDownloadFinished) window.updateDownloadFinished({json.dumps(result)});"
            )

    def _push_update_progress(self, received, total):
        if total > 0:
            percent = min(100, int(received * 100 / total))
        else:
            percent = -1

        self._update_download_state = {
            "downloading": True, "received": received, "total": total, "percent": percent,
        }
        payload = json.dumps({"received": received, "total": total, "percent": percent})
        self._emit_ui_js(
            f"if(window.updateDownloadProgress) window.updateDownloadProgress({payload});"
        )

    def _emit_ui_js(self, command):
        try:
            if self._window:
                self.ui_queue.put(command)
        except Exception:
            log_exception("PYAS_Tools.ToolsMixin._emit_ui_js")
            pass

    def get_update_download_state(self):
        """供更新弹窗重开时恢复进度/终态。"""
        state = getattr(self, "_update_download_state", None)

        if state is None:
            with self.lock_update:
                if getattr(self, "_update_downloading", False):
                    return {"downloading": True, "received": 0, "total": 0, "percent": -1}
            return {"downloading": False}

        return dict(state)

    def run_update_installer(self, file_path):
        try:
            path = os.path.expandvars(str(file_path)).strip('"').strip("'")
            downloads_dir = os.path.normcase(os.path.join(self.path_user, "Downloads"))

            if os.path.normcase(os.path.dirname(path)) != downloads_dir:
                return False

            if not os.path.isfile(path):
                return False

            if not os.path.basename(path).lower().endswith((".exe", ".msi")):
                return False

            os.startfile(path)
            return True

        except Exception as error:
            log_exception("PYAS_Tools.ToolsMixin.run_update_installer")
            self.write_log("WARN", "Update Install", detail=str(error), success=False)
            return False

    def calc_file_hash(self, file_path, block_size=65536):
        try:
            h = hashlib.sha256()

            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(block_size), b""):
                    h.update(chunk)

            return h.hexdigest()
        except Exception:
            log_exception("PYAS_Tools.ToolsMixin.calc_file_hash:285")
            return None
