"""Find the application's native window without trusting its title alone."""
import ctypes
import ctypes.wintypes as W
import os
from functools import lru_cache


@lru_cache(maxsize=1)
def _apis():
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    for api, args, result in (
        (user32.FindWindowExW, [W.HWND, W.HWND, W.LPCWSTR, W.LPCWSTR], W.HWND),
        (user32.GetClassNameW, [W.HWND, W.LPWSTR, ctypes.c_int], ctypes.c_int),
        (user32.GetWindowThreadProcessId, [W.HWND, ctypes.POINTER(W.DWORD)], W.DWORD),
        (kernel32.OpenProcess, [W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
        (kernel32.QueryFullProcessImageNameW, [W.HANDLE, W.DWORD, W.LPWSTR, ctypes.POINTER(W.DWORD)], W.BOOL),
        (kernel32.CloseHandle, [W.HANDLE], W.BOOL),
    ):
        api.argtypes, api.restype = args, result
    return user32, kernel32


def find_main_window(title, own_pid=None):
    user32, kernel32 = _apis()
    previous = None
    while True:
        hwnd = user32.FindWindowExW(None, previous, None, title)
        if not hwnd:
            return None
        previous = hwnd
        name = ctypes.create_unicode_buffer(256)
        if not user32.GetClassNameW(hwnd, name, len(name)) or not name.value.startswith('WindowsForms10.Window.'):
            continue
        pid = W.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value:
            continue
        if own_pid is not None:
            if pid.value == own_pid:
                return hwnd
            continue
        process = kernel32.OpenProcess(0x1000, False, pid.value)
        if not process:
            continue
        try:
            path = ctypes.create_unicode_buffer(32768)
            size = W.DWORD(len(path))
            if kernel32.QueryFullProcessImageNameW(process, 0, path, ctypes.byref(size)):
                executable = os.path.basename(path.value).lower()
                if executable == 'pyas.exe' or executable in ('python.exe', 'pythonw.exe'):
                    return hwnd
        finally:
            kernel32.CloseHandle(process)
