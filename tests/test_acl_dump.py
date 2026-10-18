"""Temporary diagnostic: dump the real ACEs of a Program Files install."""
import ctypes, ctypes.wintypes as wt, os, sys, unittest
import PYAS_PolicyWindows as windows


@unittest.skipUnless(os.name == 'nt', 'Windows only')
class AclDump(unittest.TestCase):
    def test_dump(self):
        target = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'PYAS', 'PYAS.exe')
        if not os.path.isfile(target):
            target = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'kernel32.dll')
        print('TARGET', target, file=sys.stderr)
        handle = windows._open(target, 0x20080, 3, 0x00200000 | 0x80)
        advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        kernel = windows._kernel()
        owner, dacl, desc = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        get = advapi.GetSecurityInfo
        get.argtypes = [wt.HANDLE, ctypes.c_int, wt.DWORD, ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        get.restype = wt.DWORD
        rc = get(handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(desc))
        print('GetSecurityInfo rc=', rc, 'dacl=', dacl.value, file=sys.stderr)
        convert = advapi.ConvertSidToStringSidW
        convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.LPWSTR)]; convert.restype = wt.BOOL
        kernel.LocalFree.argtypes = [ctypes.c_void_p]; kernel.LocalFree.restype = ctypes.c_void_p
        def sid(p):
            t = wt.LPWSTR()
            if not convert(p, ctypes.byref(t)):
                return '?'
            try: return t.value
            finally: kernel.LocalFree(ctypes.cast(t, ctypes.c_void_p))
        print('OWNER', sid(owner), file=sys.stderr)
        class AclSize(ctypes.Structure):
            _fields_ = [('count', wt.DWORD), ('used', wt.DWORD), ('free', wt.DWORD)]
        size = AclSize()
        advapi.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.c_int]
        advapi.GetAclInformation.restype = wt.BOOL
        advapi.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), 2)
        ace_fn = advapi.GetAce
        ace_fn.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(ctypes.c_void_p)]; ace_fn.restype = wt.BOOL
        print('ACE COUNT', size.count, file=sys.stderr)
        for i in range(size.count):
            ace = ctypes.c_void_p()
            ace_fn(dacl, i, ctypes.byref(ace))
            kind = ctypes.c_ubyte.from_address(ace.value).value
            flags = ctypes.c_ubyte.from_address(ace.value + 1).value
            mask = ctypes.c_uint32.from_address(ace.value + 4).value
            s = sid(ace.value + 8)
            write = windows._ace_allows_write(mask, False)
            marker = 'WRITE' if write else '     '
            untrusted = 'UNTRUSTED' if s in windows.UNTRUSTED_SIDS else ''
            print(f'ACE {i} type={kind} flags=0x{flags:02x} mask=0x{mask:08x} {marker} {untrusted} {s}', file=sys.stderr)
        print('secure_path=', windows.secure_path(target, installation=True, details={}), file=sys.stderr)
        print('REDIRECTED_DETAILS=', windows.installation_trust_issue(), file=sys.stderr)


if __name__ == '__main__':
    unittest.main()
