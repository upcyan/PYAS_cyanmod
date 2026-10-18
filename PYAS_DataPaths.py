"""OS-owned locations; user data is never a policy authority."""
import ctypes
import ctypes.wintypes as wt
import os
from pathlib import Path


def known_folder(csidl):
    if os.name != 'nt':
        raise OSError('Windows known folders are unavailable')
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    function = shell.SHGetFolderPathW
    function.argtypes = [wt.HWND, ctypes.c_int, wt.HANDLE, wt.DWORD, wt.LPWSTR]
    function.restype = ctypes.c_long
    value = ctypes.create_unicode_buffer(32768)
    if function(None, csidl, None, 0, value) != 0 or not value.value:
        raise OSError('Cannot resolve Windows data directory')
    return value.value


def user_data_dir():
    base = known_folder(0x1C) if os.name == 'nt' else (os.environ.get('LOCALAPPDATA')
        or os.environ.get('XDG_DATA_HOME') or str(Path.home() / '.local' / 'share'))
    return os.path.join(base, 'PYAS')


def policy_data_dir():
    return os.path.join(known_folder(0x23), 'PYAS.Policy')


def legacy_config_path():
    return os.path.join(known_folder(0x23), 'PYAS', 'Config.json')
