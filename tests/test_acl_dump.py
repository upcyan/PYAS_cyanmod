"""Temporary diagnostic: dump ACEs for the whole ancestor chain."""
import ctypes, ctypes.wintypes as wt, os, sys, unittest
import PYAS_PolicyWindows as windows


def dump(path, directory, ancestor):
    print('=== ' + path, file=sys.stderr)
    details = {}
    ok = windows.secure_path(path, directory=directory, installation=True,
                             ancestor=ancestor, details=details)
    print('secure_path=' + str(ok) + ' details=' + str(details), file=sys.stderr)
    try:
        handle = windows._open(path, 0x20080, 3, 0x00200000 | (0x02000000 if directory else 0x80))
    except OSError as error:
        print('open failed ' + str(error), file=sys.stderr)
        return
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = windows._kernel()
    owner, dacl, desc = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    get = advapi.GetSecurityInfo
    get.argtypes = [wt.HANDLE, ctypes.c_int, wt.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    get.restype = wt.DWORD
    if get(handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(desc)):
        print('GetSecurityInfo failed', file=sys.stderr); return
    convert = advapi.ConvertSidToStringSidW
    convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.LPWSTR)]; convert.restype = wt.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]; kernel.LocalFree.restype = ctypes.c_void_p
    def sid(p):
        t = wt.LPWSTR()
        if not convert(p, ctypes.byref(t)): return '?'
        try: return t.value
        finally: kernel.LocalFree(ctypes.cast(t, ctypes.c_void_p))
    print('OWNER ' + sid(owner), file=sys.stderr)
    class AclSize(ctypes.Structure):
        _fields_ = [('count', wt.DWORD), ('used', wt.DWORD), ('free', wt.DWORD)]
    size = AclSize()
    advapi.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.c_int]
    advapi.GetAclInformation.restype = wt.BOOL
    advapi.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), 2)
    ace_fn = advapi.GetAce
    ace_fn.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(ctypes.c_void_p)]; ace_fn.restype = wt.BOOL
    for i in range(size.count):
        ace = ctypes.c_void_p(); ace_fn(dacl, i, ctypes.byref(ace))
        kind = ctypes.c_ubyte.from_address(ace.value).value
        flags = ctypes.c_ubyte.from_address(ace.value + 1).value
        mask = ctypes.c_uint32.from_address(ace.value + 4).value
        s = sid(ace.value + 8)
        w = windows._ace_allows_write(mask, bool(directory))
        print('ACE%d type=%d flags=0x%02x mask=0x%08x %s %s %s' % (
            i, kind, flags, mask, 'WRITE' if w else '     ',
            'UNTRUSTED' if s in windows.UNTRUSTED_SIDS else '', s), file=sys.stderr)


@unittest.skipUnless(os.name == 'nt', 'Windows only')
class AclDump(unittest.TestCase):
    def test_dump(self):
        program_files = os.environ.get('ProgramFiles', r'C:\Program Files')
        target = os.path.join(program_files, 'PYAS', 'PYAS.exe')
        if not os.path.isfile(target):
            print('NOT INSTALLED; dumping Program Files itself', file=sys.stderr)
            dump(program_files, True, False)
            dump(program_files, True, True)
            parent = os.path.dirname(program_files)
            while parent:
                dump(parent, True, True)
                nxt = os.path.dirname(parent)
                if nxt == parent: break
                parent = nxt
            return
        dump(target, False, False)
        parent = os.path.dirname(target)
        base = os.path.normcase(os.path.realpath(program_files))
        while parent and os.path.normcase(parent) != base:
            dump(parent, True, True)
            parent = os.path.dirname(parent)
        dump(base, True, True)


if __name__ == '__main__':
    unittest.main()
