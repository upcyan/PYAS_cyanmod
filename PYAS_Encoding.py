"""Decode redirected Windows command output without discarding invalid bytes."""
import ctypes
import locale
import os


def decode_process_output(data):
    if not data:
        return ''
    if isinstance(data, str):
        return data
    try:
        return data.decode('utf-8-sig')
    except UnicodeDecodeError:
        # Windows PowerShell 5 and older installed scripts can still emit ACP.
        encoding = (f'cp{ctypes.windll.kernel32.GetACP()}' if os.name == 'nt'
                    else locale.getpreferredencoding(False))
        return data.decode(encoding, errors='backslashreplace')
