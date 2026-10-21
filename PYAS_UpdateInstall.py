"""Pinned-file installer launch for the fork; never executes an unchecked path.

Windows binding contract:
https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow
"""
from contextlib import ExitStack
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import threading
from PYAS_FileTrust import locked_read, sha256_stream


class InstallLaunchUncertain(RuntimeError):
    """The shell accepted a launch but did not return a process to monitor."""


# 应用内「一键升级」用静默参数:Inno 在 /VERYSILENT 下不走任何向导页(含 Ready 页)。
# PYASAUTO=1 是给安装脚本认的信号 —— 只有带它才在静默安装后自动拉起新版。
INNO_SILENT_PARAMETERS = ('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/PYASAUTO=1')


def launch_verified_installer(path, expected_digest, on_exit=None, silent=True):
    if os.name != 'nt':
        raise OSError('Native installer launch requires Windows')
    path = os.path.realpath(os.path.abspath(path))
    if not path.lower().endswith(('.exe', '.msi')):
        raise ValueError('Unsupported installer type')
    stack = ExitStack()
    try:
        stream = stack.enter_context(locked_read(path))
        if sha256_stream(stream) != expected_digest:
            raise ValueError('Installer changed after download')
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        shell = ctypes.WinDLL('shell32', use_last_error=True)
        kernel.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
        kernel.WaitForSingleObject.restype = wt.DWORD
        kernel.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
        kernel.GetExitCodeProcess.restype = wt.BOOL
        kernel.CloseHandle.argtypes = [wt.HANDLE]
        kernel.CloseHandle.restype = wt.BOOL

        class IconUnion(ctypes.Union):
            _fields_ = [('hIcon', wt.HANDLE), ('hMonitor', wt.HANDLE)]
        class ShellExecuteInfo(ctypes.Structure):
            _anonymous_ = ('icon',)
            _fields_ = [('cbSize', wt.DWORD), ('fMask', wt.ULONG), ('hwnd', wt.HWND),
                ('lpVerb', wt.LPCWSTR), ('lpFile', wt.LPCWSTR), ('lpParameters', wt.LPCWSTR),
                ('lpDirectory', wt.LPCWSTR), ('nShow', ctypes.c_int), ('hInstApp', wt.HINSTANCE),
                ('lpIDList', ctypes.c_void_p), ('lpClass', wt.LPCWSTR), ('hkeyClass', wt.HKEY),
                ('dwHotKey', wt.DWORD), ('icon', IconUnion), ('hProcess', wt.HANDLE)]
        execute = shell.ShellExecuteExW
        execute.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
        execute.restype = wt.BOOL
        info = ShellExecuteInfo()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = 0x40 | 0x100 | 0x400  # NOCLOSEPROCESS, NOASYNC, FLAG_NO_UI
        info.lpVerb = 'open'
        info.lpDirectory = os.path.dirname(path)
        info.nShow = 1
        if path.lower().endswith('.msi'):
            # Explicit executable avoids DDE/file-association delegation.
            system = ctypes.create_unicode_buffer(32768)
            kernel.GetSystemDirectoryW.argtypes = [wt.LPWSTR, wt.UINT]
            kernel.GetSystemDirectoryW.restype = wt.UINT
            length = kernel.GetSystemDirectoryW(system, len(system))
            if not length or length >= len(system):
                raise ctypes.WinError(ctypes.get_last_error())
            info.lpFile = os.path.join(system.value, 'msiexec.exe')
            info.lpParameters = subprocess.list2cmdline(['/i', path])
        else:
            info.lpFile = path

            if silent:
                info.lpParameters = subprocess.list2cmdline(INNO_SILENT_PARAMETERS)
        ready = threading.Event()
        record = {'handle': None}
        owned = stack.pop_all()
        def monitor():
            ready.wait()
            handle = record['handle']
            exit_code = None
            try:
                if handle and kernel.WaitForSingleObject(handle, 0xFFFFFFFF) == 0:
                    code = wt.DWORD()
                    if kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
                        exit_code = int(code.value)
            finally:
                if handle:
                    kernel.CloseHandle(handle)
                owned.close()
                if handle and on_exit:
                    try:
                        on_exit(exit_code)
                    except Exception:
                        pass
        # Allocate the monitor before launch; resource exhaustion cannot launch an
        # installer and then accidentally report it as never started.
        try:
            threading.Thread(target=monitor, daemon=True, name='PYAS.UpdateInstaller').start()
        except BaseException:
            owned.close()
            raise
        try:
            if not execute(ctypes.byref(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if not info.hProcess:
                raise InstallLaunchUncertain('Shell accepted the installer but returned no process handle')
            record['handle'] = info.hProcess
        finally:
            ready.set()
        return True
    finally:
        stack.close()
