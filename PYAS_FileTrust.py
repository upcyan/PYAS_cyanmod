"""Fork-owned stable file reads for signature and installer trust decisions.

On Windows FILE_SHARE_READ denies concurrent writers and replacement until close.
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
The POSIX branch supports offline tests only; it is not a Windows sharing guarantee.
"""
from contextlib import contextmanager
import ctypes
import ctypes.wintypes
import hashlib
import os
import stat


def system_directory():
    """Use the OS directory API, never a caller-controlled SystemRoot/PATH value."""
    if os.name != 'nt':
        raise OSError('Windows system directory is unavailable')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    function = kernel.GetSystemDirectoryW
    function.argtypes = [ctypes.wintypes.LPWSTR, ctypes.wintypes.UINT]
    function.restype = ctypes.wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = function(buffer, len(buffer))
    if not length or length >= len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value


@contextmanager
def locked_read(path):
    path = os.path.abspath(os.fspath(path))
    if os.name == "nt":
        import msvcrt
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD, ctypes.c_void_p, ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD, ctypes.wintypes.HANDLE]
        create.restype = ctypes.wintypes.HANDLE
        close = kernel.CloseHandle
        close.argtypes = [ctypes.wintypes.HANDLE]
        close.restype = ctypes.wintypes.BOOL
        handle = create(path, 0x80000000, 0x00000001, None, 3, 0x80, None)
        if not handle or handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            fd = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
        except BaseException:
            close(handle)
            raise
        try:
            stream = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
    else:
        stream = open(path, "rb")
    with stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise OSError("Trust checks require a regular file")
        yield stream


def sha256_stream(stream):
    position = stream.tell()
    try:
        stream.seek(0)
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        return digest.hexdigest()
    finally:
        stream.seek(position)
