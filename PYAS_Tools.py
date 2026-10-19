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
from PYAS_Version import VERSION, UPSTREAM_REPO, UPSTREAM_TRACKED
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
                    # ProxyEnable=0 时 ProxyServer 只是残留配置,照样用会把请求
                    # 打到已停用的本地端口(实测过期端口直接报 SSLError)
                    enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")

                except FileNotFoundError:
                    enabled = 0

                try:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")

                except FileNotFoundError:
                    server = ""

                if enabled and server:
                    # IE 设置两种写法:整体 "host:port" 与分协议 "http=..;https=.."
                    if "=" in server:
                        entries = dict(
                            part.split("=", 1) for part in server.split(";") if "=" in part
                        )

                        for value in (entries.get("https"), entries.get("http")):
                            if value and value.strip():
                                candidates.append("http://" + value.strip())

                    else:
                        candidates.append("http://" + server)

                try:
                    pac, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                    match = re.match(r"https?://([^/:]+):(\d+)", pac or "")

                    if match and match.group(1) in ("127.0.0.1", "localhost"):
                        candidates.append(f"http://127.0.0.1:{match.group(2)}")

                except FileNotFoundError:
                    pass

        except Exception:
            pass

        # WinHTTP(netsh winhttp set proxy)与 IE 设置是两套:只在 WinHTTP 里配了代理时,
        # 上面那段读不到。这个二进制是「DWORD + 若干(长度+UTF-16 字符串)」。
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections",
            ) as key:
                blob = winreg.QueryValueEx(key, "WinHttpSettings")[0]
            offset = 4
            length = int.from_bytes(blob[offset:offset + 4], "little")
            server = blob[offset + 4:offset + 4 + length].decode("utf-16-le", "ignore").strip()
            if server:
                candidates.append(server if "://" in server else "http://" + server)
        except (FileNotFoundError, OSError, ValueError, IndexError, AttributeError):
            pass

        seen = set()
        unique = []

        for item in candidates:
            if item not in seen:
                seen.add(item)
                unique.append(item)

        return unique

    def _github_get(self, url, **kwargs):
        """按渠道依次取 GitHub 数据:直连 → 系统代理 → 元数据镜像。

        只要有一个渠道能通就返回;403/429 是 GitHub 给的真实状态,原样交给调用方。
        镜像只用来判断「有没有新版本」,拿到的东西不参与安装包完整性判定。
        """
        kwargs.setdefault("timeout", 15)
        kwargs.setdefault("headers", self.GITHUB_RELEASE_HEADERS)

        from PYAS_Updates import RELEASE_MIRRORS

        attempts = [(None, url)]
        for proxy in self._system_proxy_candidates():
            attempts.append((proxy, url))
        for mirror in RELEASE_MIRRORS:
            attempts.append((None, mirror + url))

        last = None
        for proxy, target in attempts:
            try:
                response = requests.get(target, **kwargs) if proxy is None else requests.get(
                    target, proxies={"http": proxy, "https": proxy}, **kwargs)
            except requests.RequestException as error:
                last = error
                continue
            if response.status_code in (200, 403, 429):
                return response
            last = response
            response.close()

        if isinstance(last, requests.Response):
            return last
        if isinstance(last, Exception):
            raise last
        raise requests.RequestException('update source unavailable')

    def _is_dev_channel(self):
        """当前安装包是不是开发者模式（本地构建）。

        渠道在打包时写入生成模块 PYAS_Build.py；读不到就按普通模式，
        也就是发布包的行为。
        """
        try:
            import PYAS_Channel

            return bool(PYAS_Channel.IS_DEV)

        except Exception:
            return False

    def _check_upstream_update(self):
        """开发者模式专有：上游 87owo/PYAS 有没有比本项目跟进版本更新的发布。

        只比对版本号并给出上游发布页，不下载上游安装包（那是另一个产品）。
        任何失败都降级成 error 字段，绝不影响本仓库自身的更新检查结果。
        """
        repository = UPSTREAM_REPO
        tracked = UPSTREAM_TRACKED
        releases_url = f'https://github.com/{repository}/releases'

        try:
            response = self._github_get(f'https://api.github.com/repos/{repository}/releases?per_page=100')

            try:
                if response.status_code == 404:
                    return {'supported': True, 'error': True, 'error_code': 'repository_unavailable', 'detail': repository}
                if response.status_code in (403, 429):
                    return {'supported': True, 'error': True, 'error_code': 'rate_limited', 'detail': f'HTTP {response.status_code}'}
                response.raise_for_status()
                releases = response.json()

            finally:
                response.close()

            if not isinstance(releases, list):
                return {'supported': True, 'error': True, 'error_code': 'invalid_response'}

            candidates = [r for r in releases if isinstance(r, dict) and not r.get('draft') and not r.get('prerelease')
                and re.fullmatch(r'[vV]?\d+(?:\.\d+){1,3}', str(r.get('tag_name') or ''))]
            latest_release = max(candidates, key=lambda r: tuple(int(n) for n in re.findall(r'\d+', r['tag_name'])) +
                (0,) * (5 - len(re.findall(r'\d+', r['tag_name']))), default=None)

            if latest_release is None:
                return {'supported': True, 'repository': repository, 'tracked': tracked, 'latest': tracked,
                    'has_update': False, 'url': releases_url}

            latest = str(latest_release.get('tag_name') or latest_release.get('name') or '').strip()

            return {
                'supported': True,
                'repository': repository,
                'tracked': tracked,
                'latest': latest,
                'has_update': bool(latest) and tracked != latest and not self.compare_versions(tracked, latest),
                'url': releases_url,
                'body': str(latest_release.get('body') or '').strip()[:2000],
                'published_at': str(latest_release.get('published_at') or '')[:10],
            }

        except requests.RequestException as error:
            log_exception('PYAS_Tools.ToolsMixin._check_upstream_update.network')
            return {'supported': True, 'error': True, 'error_code': 'network_error', 'detail': f'{type(error).__name__}: {str(error)[:160]}'}
        except Exception:
            log_exception('PYAS_Tools.ToolsMixin._check_upstream_update')
            return {'supported': True, 'error': True, 'error_code': 'invalid_response'}

    def check_update(self):
        """Only the latest completed check may publish an installable selection."""
        from PYAS_Updates import normalize_asset, update_control_lock
        with update_control_lock(self):
            generation = getattr(self, '_update_check_generation', 0) + 1
            self._update_check_generation = generation
            self._checked_update_asset = None
        result = self._check_self_update()
        if isinstance(result, dict) and self._is_dev_channel():
            result['upstream'] = self._check_upstream_update()
        with update_control_lock(self):
            if generation != self._update_check_generation:
                return {'error': True, 'error_code': 'superseded'}
            if isinstance(result, dict) and not result.get('error'):
                try:
                    selected = normalize_asset(result.get('asset'))
                except ValueError:
                    return {'error': True, 'error_code': 'invalid_response'}
                result['asset'] = selected
                self._checked_update_asset = selected
        return result

    def _check_self_update(self):
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
                    # 同一发布里的 .sha256 作为第二份校验码:API digest 之外独立成件,
                    # 两个都对得上才允许安装
                    checksum_url = ''
                    for sibling in j.get('assets') or []:
                        if str(sibling.get('name') or '') != name + '.sha256':
                            continue
                        candidate_url = str(sibling.get('browser_download_url') or '')
                        if candidate_url.startswith('https://github.com/%s/releases/download/' % repository):
                            checksum_url = candidate_url
                        break

                    asset = {
                        "name": name,
                        "url": item.get("browser_download_url"),
                        "size": int(item.get("size") or 0),
                        'digest': item.get('digest'),
                        'checksum_url': checksum_url,
                        'version': latest,
                    }

                    if lower.endswith(".exe"):
                        break

            if latest:
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
            return {'error': True, 'error_code': 'network_error', 'detail': f'{type(error).__name__}: {str(error)[:160]}'}
        except Exception:
            log_exception("PYAS_Tools.ToolsMixin.check_update:274")
            pass

        return {"error": True, 'error_code': 'invalid_response'}

    def _get_update_manager(self):
        from PYAS_Updates import UpdateDownloadManager, update_control_lock
        with update_control_lock(self):
            manager = getattr(self, '_update_download_manager', None)
            if manager is None:
                manager = self._update_download_manager = UpdateDownloadManager(
                    self.path_user, self._github_get, self._emit_ui_js, self.write_log)
            manager.select(getattr(self, '_checked_update_asset', None))
            return manager

    def download_update(self, url, file_name=None, download_id=None):
        try:
            return self._get_update_manager().start(url, file_name, download_id)
        except (OSError, ValueError) as error:
            return {'success': False, 'error': str(error)}

    def _emit_ui_js(self, command):
        try:
            if self._window:
                self.ui_queue.put(command)
        except Exception:
            log_exception("PYAS_Tools.ToolsMixin._emit_ui_js")
            pass

    def get_update_download_state(self):
        """Restore only a job-identified snapshot; no unsynchronised global flags."""
        return self._get_update_manager().snapshot()

    def run_update_installer(self, file_path, download_id=None):
        try:
            return self._get_update_manager().install(file_path, download_id)
        except (OSError, ValueError) as error:
            self.write_log('WARN', 'Update Install', detail=str(error), success=False)
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
