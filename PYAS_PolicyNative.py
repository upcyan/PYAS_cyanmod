"""Minimal Win32 process bindings for the fixed policy-helper entry."""
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import struct
import subprocess
import sys
from PYAS_Policy import PolicyDenied


def _kernel(): return ctypes.WinDLL('kernel32', use_last_error=True)


def launcher_path():
    """The installed static launcher is the only sanctioned way to start an
    independent frozen instance. The elevated helper must go through it so the
    PyInstaller onefile bootloader resets the inherited parent environment
    (PYINSTALLER_RESET_ENVIRONMENT=1) instead of reusing the GUI's _MEI state."""
    from PYAS_PolicyWindows import secure_path
    path = os.path.join(os.path.dirname(sys.executable), 'PYAS_Launcher.exe')
    if not os.path.isfile(path):
        raise PolicyDenied('Authorization launcher is missing from the installation directory')
    details = {}
    if not secure_path(path, installation=True, details=details):
        raise PolicyDenied('Authorization launcher is not a trusted installation component: '
                           + json.dumps(details, ensure_ascii=False))
    return path


def _elevate_arguments(request, digest):
    """Fixed launcher, fixed verb, fixed helper flag; no caller-controlled text."""
    launcher = launcher_path()
    return launcher, subprocess.list2cmdline(
        ['--wait', '--pyas-policy-helper', request, digest])


def elevate_helper(request, digest):
    class Icon(ctypes.Union):
        _fields_ = [('icon', wt.HANDLE), ('monitor', wt.HANDLE)]
    class ExecuteInfo(ctypes.Structure):
        _fields_ = [('cbSize', wt.DWORD), ('fMask', wt.ULONG), ('hwnd', wt.HWND),
            ('lpVerb', wt.LPCWSTR), ('lpFile', wt.LPCWSTR), ('lpParameters', wt.LPCWSTR),
            ('lpDirectory', wt.LPCWSTR), ('nShow', ctypes.c_int), ('hInstApp', wt.HINSTANCE),
            ('lpIDList', ctypes.c_void_p), ('lpClass', wt.LPCWSTR), ('hkeyClass', wt.HKEY),
            ('dwHotKey', wt.DWORD), ('icon', Icon), ('hProcess', wt.HANDLE)]
    file, parameters = _elevate_arguments(request, digest)
    info = ExecuteInfo()
    info.cbSize = ctypes.sizeof(info); info.fMask = 0x40 | 0x100 | 0x400
    info.lpVerb = 'runas'; info.lpFile = file
    info.lpParameters = parameters
    info.lpDirectory = os.path.dirname(sys.executable); info.nShow = 0
    function = ctypes.WinDLL('shell32', use_last_error=True).ShellExecuteExW
    function.argtypes = [ctypes.POINTER(ExecuteInfo)]; function.restype = wt.BOOL
    if not function(ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not info.hProcess:
        raise PolicyDenied('Authorization launch could not be tracked; no policy change was submitted')
    return info.hProcess

def process_exit_code(handle):
    kernel = _kernel()
    wait = kernel.WaitForSingleObject
    wait.argtypes = [wt.HANDLE, wt.DWORD]; wait.restype = wt.DWORD
    result = wait(handle, 0)
    if result == 0x102: return None
    if result != 0: raise ctypes.WinError(ctypes.get_last_error())
    code = wt.DWORD()
    get = kernel.GetExitCodeProcess
    get.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]; get.restype = wt.BOOL
    if not get(handle, ctypes.byref(code)): raise ctypes.WinError(ctypes.get_last_error())
    return int(code.value)


def _pin_local_parents(path):
    from PYAS_PolicyWindows import _open, _close
    path = os.path.normpath(os.path.abspath(path))
    drive, _ = os.path.splitdrive(path)
    if len(drive) != 2 or drive[1] != ':' or path.startswith('\\'):
        raise PolicyDenied('Local fixed-drive request required')
    kernel = _kernel()
    drive_type = kernel.GetDriveTypeW
    drive_type.argtypes = [wt.LPCWSTR]; drive_type.restype = wt.UINT
    if drive_type(drive + os.sep) != 3:
        raise PolicyDenied('Remote policy requests are not supported')
    info = kernel.GetFileInformationByHandleEx
    info.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]; info.restype = wt.BOOL
    parents = []
    current = os.path.dirname(path)
    while current and os.path.dirname(current) != current:
        parents.append(current); current = os.path.dirname(current)
    parents.reverse()
    handles = []
    try:
        for parent in parents:
            handle = _open(parent, 0x20080, 3, 0x02200000)
            handles.append(handle)
            attrs = (wt.DWORD * 2)()
            if not info(handle, 9, ctypes.byref(attrs), ctypes.sizeof(attrs)) or attrs[0] & 0x400:
                raise PolicyDenied('Reparse-point policy requests are not supported')
        return path, handles
    except BaseException:
        for handle in reversed(handles): _close(handle)
        raise


def verify_request_owner(path, digest):
    path, handles = _pin_local_parents(path)
    try:
        _verify_owned_channel(path, digest)
        return handles
    except BaseException:
        from PYAS_PolicyWindows import _close
        for handle in reversed(handles): _close(handle)
        raise


def _verify_owned_channel(path, digest):
    """Bind the request to an actual open handle of the running installed GUI."""
    import msvcrt
    from PYAS_PolicyWindows import _open, _close, installed_helper_trusted
    if not installed_helper_trusted():
        raise PolicyDenied('Untrusted helper installation')
    if not os.path.isabs(path) or path.startswith('\\'):
        raise PolicyDenied('Local request required')
    handle = _open(path, 0x80000000, 3, 0x00200000)
    try: descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
    except BaseException:
        _close(handle)
        raise
    with os.fdopen(descriptor, 'rb') as stream:
        size = struct.unpack('<I', stream.read(4))[0]
        if size < 2 or size > 60000: raise PolicyDenied('Invalid request header')
        raw = stream.read(size)
        if hashlib.sha256(raw).hexdigest() != digest: raise PolicyDenied('Request hash mismatch')
        header = json.loads(raw.decode('utf-8'))
        import re
        nonce = str(header.get('nonce') or '')
        if header.get('protocol') != 1 or not re.fullmatch(r'[0-9a-f]{32}', nonce):
            raise PolicyDenied('Invalid request identity')
        if os.path.basename(path) != nonce + '.request' or os.path.basename(os.path.dirname(path)) != 'PolicyRequests':
            raise PolicyDenied('Invalid request location')
        pid, original = header.get('pid'), header.get('handle')
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 or not isinstance(original, int):
            raise PolicyDenied('Invalid request owner')
        kernel = _kernel()
        open_process = kernel.OpenProcess
        open_process.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]; open_process.restype = wt.HANDLE
        parent = open_process(0x1040, False, pid)
        if not parent: raise ctypes.WinError(ctypes.get_last_error())
        duplicate = wt.HANDLE()
        try:
            query = kernel.QueryFullProcessImageNameW
            query.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]; query.restype = wt.BOOL
            buffer = ctypes.create_unicode_buffer(32768); length = wt.DWORD(len(buffer))
            if not query(parent, 0, buffer, ctypes.byref(length)):
                raise ctypes.WinError(ctypes.get_last_error())
            if os.path.normcase(os.path.abspath(buffer.value)) != os.path.normcase(os.path.abspath(sys.executable)):
                raise PolicyDenied('Request owner is not this application')
            kernel.GetCurrentProcess.argtypes = []; kernel.GetCurrentProcess.restype = wt.HANDLE
            dup = kernel.DuplicateHandle
            dup.argtypes = [wt.HANDLE, wt.HANDLE, wt.HANDLE, ctypes.POINTER(wt.HANDLE), wt.DWORD, wt.BOOL, wt.DWORD]
            dup.restype = wt.BOOL
            if not dup(parent, original, kernel.GetCurrentProcess(), ctypes.byref(duplicate), 0x12019F, False, 0):
                raise ctypes.WinError(ctypes.get_last_error())
            fd = msvcrt.open_osfhandle(int(duplicate.value), os.O_RDONLY | os.O_BINARY)
            duplicate = wt.HANDLE()
            with os.fdopen(fd, 'rb') as owner_file:
                owner_file.seek(0)
                owner_size = struct.unpack('<I', owner_file.read(4))[0]
                if owner_size != size or hashlib.sha256(owner_file.read(owner_size)).hexdigest() != digest:
                    raise PolicyDenied('Request is not owned by the GUI')
                left, right = os.fstat(owner_file.fileno()), os.fstat(stream.fileno())
                if (left.st_dev, left.st_ino) != (right.st_dev, right.st_ino):
                    raise PolicyDenied('Request file was replaced')
                try:
                    writable = _open(path, 0x40000000, 3)
                except OSError as error:
                    if getattr(error, 'winerror', None) != 32: raise PolicyDenied('Request sharing mode is invalid')
                else:
                    _close(writable)
                    raise PolicyDenied('Request is not exclusively writable by the GUI')
        finally:
            if duplicate.value: _close(duplicate.value)
            _close(parent)
