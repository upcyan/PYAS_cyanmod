"""Windows administrator-only policy store and one-shot, scope-limited UAC broker.

The elevated frozen entry imports no GUI/diagnostics. Its only privileged output
is the fixed ProgramData/PYAS.Policy directory. Request content is data, not code.
"""
import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import struct
import subprocess
import sys
import threading
import time
from uuid import uuid4
from PYAS_DataPaths import policy_data_dir, user_data_dir, legacy_config_path
from PYAS_FileTrust import locked_read, system_directory
from PYAS_Policy import (POLICY_KEYS, BOOL_KEYS, STRING_KEYS, NUMBER_KEYS, LIST_KEYS,
                         FORMAT, MAX_BYTES, PolicyDenied, PolicyPending, bounded_json)

PAYLOAD_OFFSET = 65536
ADMIN_SIDS = {'S-1-5-18', 'S-1-5-32-544'}
INSTALLER_SIDS = ADMIN_SIDS | {'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'}
WRITE_ACCESS = 0x500D0156


def _kernel():
    return ctypes.WinDLL('kernel32', use_last_error=True)


def _open(path, access, share, flags=0x80, disposition=3):
    kernel = _kernel()
    function = kernel.CreateFileW
    function.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
    function.restype = wt.HANDLE
    handle = function(str(path), access, share, None, disposition, flags, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def _close(handle):
    if handle:
        function = _kernel().CloseHandle
        function.argtypes = [wt.HANDLE]; function.restype = wt.BOOL
        function(handle)


def secure_path(path, directory=False, installation=False, ancestor=False, details=None):
    """Verify the opened object, not an untrusted filename or inherited owner."""
    if details is not None: details.update(path=str(path), reason='security descriptor unavailable')
    if os.name != 'nt': return False
    handle = None; descriptor = ctypes.c_void_p()
    try:
        handle = _open(path, 0x20080, 3, 0x00200000 | (0x02000000 if directory else 0x80))
        kernel = _kernel(); advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        attrs = (wt.DWORD * 2)()
        info = kernel.GetFileInformationByHandleEx
        info.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]; info.restype = wt.BOOL
        if not info(handle, 9, ctypes.byref(attrs), ctypes.sizeof(attrs)) or attrs[0] & 0x400:
            return False
        owner, dacl = ctypes.c_void_p(), ctypes.c_void_p()
        get = advapi.GetSecurityInfo
        get.argtypes = [wt.HANDLE, ctypes.c_int, wt.DWORD, ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        get.restype = wt.DWORD
        if get(handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)) or not dacl.value:
            return False
        control, revision = ctypes.c_ushort(), wt.DWORD()
        control_fn = advapi.GetSecurityDescriptorControl
        control_fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(wt.DWORD)]
        control_fn.restype = wt.BOOL
        if not control_fn(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            return False
        convert = advapi.ConvertSidToStringSidW
        convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.LPWSTR)]; convert.restype = wt.BOOL
        kernel.LocalFree.argtypes = [ctypes.c_void_p]; kernel.LocalFree.restype = ctypes.c_void_p
        def sid_text(pointer):
            text = wt.LPWSTR()
            if not convert(pointer, ctypes.byref(text)): return ''
            try: return text.value
            finally: kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        trusted = INSTALLER_SIDS if installation else ADMIN_SIDS
        owner_sid = sid_text(owner)
        if details is not None: details['owner_sid'] = owner_sid
        if owner_sid not in trusted:
            if details is not None: details['reason'] = 'owner is not an administrator/system identity'
            return False
        class AclSize(ctypes.Structure):
            _fields_ = [('count', wt.DWORD), ('used', wt.DWORD), ('free', wt.DWORD)]
        size = AclSize()
        count = advapi.GetAclInformation
        count.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.c_int]; count.restype = wt.BOOL
        ace_fn = advapi.GetAce
        ace_fn.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(ctypes.c_void_p)]; ace_fn.restype = wt.BOOL
        if not count(dacl, ctypes.byref(size), ctypes.sizeof(size), 2) or size.count > 128: return False
        for index in range(size.count):
            ace = ctypes.c_void_p()
            if not ace_fn(dacl, index, ctypes.byref(ace)): return False
            kind = ctypes.c_ubyte.from_address(ace.value).value
            flags = ctypes.c_ubyte.from_address(ace.value + 1).value
            if installation and flags & 8: continue
            if kind == 1: continue
            if kind != 0: return False
            mask = ctypes.c_uint32.from_address(ace.value + 4).value
            restricted = 0x500D0040 if ancestor else WRITE_ACCESS
            writer_sid = sid_text(ace.value + 8)
            if mask & restricted and writer_sid not in trusted:
                if details is not None: details.update(reason='non-administrator write permission', writer_sid=writer_sid, access_mask=hex(mask))
                return False
        return True
    except (OSError, ValueError):
        return False
    finally:
        if descriptor.value:
            function = _kernel().LocalFree
            function.argtypes = [ctypes.c_void_p]; function.restype = ctypes.c_void_p
            function(descriptor)
        _close(handle)


def installation_trust_issue():
    from PYAS_DataPaths import known_folder
    try:
        base = os.path.normcase(os.path.realpath(known_folder(0x26)))
        image = os.path.normcase(os.path.realpath(sys.executable))
        if os.path.commonpath([base, image]) != base:
            return 'outside protected Program Files: ' + image
        details = {}
        if not secure_path(image, installation=True, details=details):
            return json.dumps(details, ensure_ascii=False)
        parent = os.path.dirname(image)
        while parent:
            details = {}
            if not secure_path(parent, True, installation=True, ancestor=True, details=details):
                return json.dumps(details, ensure_ascii=False)
            next_parent = os.path.dirname(parent)
            if next_parent == parent: break
            parent = next_parent
        return None
    except (OSError, ValueError) as error:
        return 'cannot resolve installation security: ' + str(error)


def installed_helper_trusted():
    return installation_trust_issue() is None


def _environment():
    directory = system_directory()
    env = {'SystemRoot': os.path.dirname(directory), 'WINDIR': os.path.dirname(directory),
        'PATH': directory, 'PSModulePath': os.path.join(directory, 'WindowsPowerShell', 'v1.0', 'Modules')}
    for key in ('TEMP', 'TMP'):
        if os.environ.get(key): env[key] = os.environ[key]
    return directory, env


BROKER = r'''
$ErrorActionPreference='Stop'
$root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'PYAS.Policy'
$target=Join-Path $root 'Config.json'
$utf8=New-Object Text.UTF8Encoding($false)
$allowed=@(__ALL_KEYS__)
$bools=@(__BOOL_KEYS__)
$strings=@(__STRING_KEYS__)
$numbers=@(__NUMBER_KEYS__)
$lists=@(__LIST_KEYS__)
$nonce='';$ack='';$ackCreated=$false;$held=$false;$reader=$null;$mutex=$null
function Secure($path,$directory) {
 if( -not  (Test-Path -LiteralPath $path)){return $false}
 if(([IO.File]::GetAttributes($path) -band  [IO.FileAttributes]::ReparsePoint) -ne  0){return $false}
 $a=if($directory){[IO.Directory]::GetAccessControl($path)}else{[IO.File]::GetAccessControl($path)}
 if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value  -notin  @('S-1-5-18','S-1-5-32-544')){return $false}
 foreach($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($r.AccessControlType -eq  'Allow'  -and  (([long]$r.FileSystemRights -band  0x500D0156) -ne  0)  -and  $r.IdentityReference.Value  -notin  @('S-1-5-18','S-1-5-32-544')){return $false}
 };return $true
}
function Security($directory){
 $a=if($directory){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
 $a.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)');return $a
}
function Write-New($path,$value){
 $bytes=$utf8.GetBytes(($value|ConvertTo-Json -Depth 32 -Compress))
 if($bytes.Length -gt 2097152){throw 'serialized policy size'}
 $s=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough,(Security $false))
 try{$s.Write($bytes,0,$bytes.Length);$s.Flush($true)}finally{$s.Dispose()}
}
function Hash($bytes){$s=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($s.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function Check-Value($key,$v) {
 if($key -cin $bools -and $v -isnot [bool]){throw 'boolean'}
 if($key -cin $strings -and ($v -isnot [string] -or $v.Length -gt 32768)){throw 'string'}
 if($key -cin $numbers -and $null -ne $v){
  if($v -is [bool] -or $v -is [string] -or $v -lt 0 -or $v -gt [long]::MaxValue){throw 'number'}
  if([double]::IsNaN([double]$v) -or [double]::IsInfinity([double]$v)){throw 'number'}
 }
 if($key -cin $lists -and ($v -isnot [array] -or $v.Count -gt 4096)){throw 'list'}
 if($key -ceq 'ai_api_key' -and $v){throw 'unencrypted credential'}
}
function Read-Policy {
 if( -not (Test-Path -LiteralPath $target)){return $null}
 if( -not (Secure $target $false)){throw 'untrusted policy file'}
 $bytes=[IO.File]::ReadAllBytes($target);if($bytes.Length -gt  2097152){throw 'policy size'}
 $d=$utf8.GetString($bytes)|ConvertFrom-Json
 if($d._format -ne  'pyas-admin-policy-v1'){throw 'policy format'}
 foreach($p in $d.PSObject.Properties){if($p.Name -cin $allowed){Check-Value $p.Name $p.Value}}
 return @{values=$d;revision=(Hash $bytes)}
}
try{
 if( -not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 5}
 $request=$utf8.GetString([Convert]::FromBase64String('__REQUEST__'))
 if($request.StartsWith('\')  -or   -not  [IO.Path]::IsPathRooted($request)){throw 'local request required'}
 $reader=[IO.FileStream]::new($request,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
 $binary=New-Object IO.BinaryReader($reader,$utf8,$true)
 $length=$binary.ReadInt32();if($length -lt  2 -or  $length -gt  60000){throw 'header size'}
 $bytes=$binary.ReadBytes($length);if((Hash $bytes) -cne  '__HEADER_HASH__'){throw 'header mismatch'}
 $h=$utf8.GetString($bytes)|ConvertFrom-Json
 if($h.protocol -ne  1 -or  $h.nonce-notmatch '^[a-f0-9]{32}$'){throw 'protocol'}
 $nonce=$h.nonce
 foreach($key in $h.scope){if($key  -cnotin  $allowed){throw 'scope'}}
 $reader.Position=65536;if($binary.ReadInt32() -eq  1){exit 2}
 $mutex=[Threading.Mutex]::new($false,'GlobalPYAS.Policy.Writer.v1')
 try{$held=$mutex.WaitOne(10000)}catch [Threading.AbandonedMutexException]{$held=$true};if( -not  $held){throw 'policy writer busy'}
 for($attempt=0;$attempt -lt  3;$attempt++){
  if(Test-Path -LiteralPath $root){
   if(Secure $root $true){break}
   [IO.Directory]::Move($root,$root+'.untrusted-'+[Guid]::NewGuid().ToString('N'))
  }
  [IO.Directory]::CreateDirectory($root,(Security $true))|Out-Null
  if(Secure $root $true){break}
 }
 if( -not (Secure $root $true)){throw 'untrusted directory'}
 $current=$null;$invalid=$false
 try{$current=Read-Policy}catch{if( -not $h.initialize){throw};$invalid=$true}
 $revision=if($current){$current.revision}else{$null}
 if($revision -cne  $h.revision){throw 'policy conflict'}
 if( -not  $current  -and   -not  $h.initialize){throw 'policy not initialized'}
 $ack=Join-Path $root ('.auth-'+$nonce+'.json')
 Write-New $ack @{stage='ready';nonce=$nonce;revision=$revision};$ackCreated=$true
 $end=[DateTime]::UtcNow.AddSeconds(120);$payload=$null
 while([DateTime]::UtcNow -lt  $end){
  $reader.Position=65536;$n=$binary.ReadInt32()
  if($n -eq  1){exit 2}
  if($n -ge  2){
   if($n -gt  2097152){throw 'payload size'}
   $raw=$binary.ReadBytes($n);if($raw.Length -ne  $n){throw 'incomplete payload'}
   $payload=$utf8.GetString($raw)|ConvertFrom-Json;break
  };Start-Sleep -Milliseconds 50
 }
 if( -not  $payload){throw 'authorization expired'}
 if($payload.nonce -cne  $nonce){throw 'nonce'}
 $latest=$null
 try{$latest=Read-Policy}catch{if( -not $h.initialize){throw}}
 $latestRevision=if($latest){$latest.revision}else{$null}
 if($latestRevision -cne  $h.revision){throw 'policy conflict'}
 $values=@{};if($latest){foreach($p in $latest.values.PSObject.Properties){if($p.Name  -cin  $allowed){$values[$p.Name]=$p.Value}}}
 foreach($p in $payload.updates.PSObject.Properties){
  $key=$p.Name;$v=$p.Value
  if($key -cnotin  $allowed -or  $key -cnotin  $h.scope){throw 'field scope'}
  if($key -cin  $bools -and  $v -isnot  [bool]){throw 'boolean'}
  if($key -cin  $strings -and  ($v -isnot  [string] -or  $v.Length -gt  32768)){throw 'string'}
  if($key -cin  $numbers -and  $null -ne  $v){if($v -is  [bool] -or  $v -is  [string] -or  $v -lt  0 -or  $v -gt  [long]::MaxValue){throw 'number'}}
  if($key -cin  $lists -and  ($v -isnot  [array] -or  $v.Count -gt  4096)){throw 'list'}
  if($key -ceq  'ai_api_key' -and  $v){throw 'unencrypted credential'}
  $values[$key]=$v
 }
 $values['_format']='pyas-admin-policy-v1';$values['_revision']=[Guid]::NewGuid().ToString('N');$values['_request']=$nonce
 $temporary=Join-Path $root ('.config-'+$nonce+'.tmp')
 Write-New $temporary $values
 if((Test-Path -LiteralPath $target) -and ( -not $latest)){[IO.File]::Move($target,(Join-Path $root ('.untrusted-config-'+$nonce+'.json')))}
 if(Test-Path -LiteralPath $target){[IO.File]::Replace($temporary,$target,$null)}else{[IO.File]::Move($temporary,$target)}
 exit 0
}catch{exit 3}finally{
 if($reader){$reader.Dispose()}
 if($ackCreated -and  $ack){try{[IO.File]::Delete($ack)}catch{}}
 if($held){$mutex.ReleaseMutex()};if($mutex){$mutex.Dispose()}
}
'''


def _script(request, digest):
    script = BROKER.replace('__REQUEST__', base64.b64encode(request.encode('utf-8')).decode('ascii')).replace('__HEADER_HASH__', digest)
    for marker, keys in (('__ALL_KEYS__', POLICY_KEYS), ('__BOOL_KEYS__', BOOL_KEYS),
                        ('__STRING_KEYS__', STRING_KEYS), ('__NUMBER_KEYS__', NUMBER_KEYS), ('__LIST_KEYS__', LIST_KEYS)):
        script = script.replace(marker, ','.join("'" + key + "'" for key in sorted(keys)))
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    if len(encoded) > 29000: raise PolicyDenied('Policy helper command is too large')
    return encoded


def _run_broker(request, digest):
    directory, env = _environment()
    command = [os.path.join(directory, 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', _script(request, digest)]
    return subprocess.Popen(command, cwd=directory, env=env, creationflags=0x08000000,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class WindowsPolicyBackend:
    def __init__(self, owner=None):
        self.owner = owner
        self.root = policy_data_dir()
        self.policy_file = os.path.join(self.root, 'Config.json')
        self.user_file = os.path.join(user_data_dir(), 'Preferences.json')
        self.legacy_file = legacy_config_path()
        self.leases = set()
        self.lock = threading.RLock()

    def read_user(self):
        try:
            with open(self.user_file, 'rb') as stream: raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES: return {}
            value = json.loads(raw.decode('utf-8'))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError): return {}

    def write_user(self, data):
        from PYAS_Storage import atomic_write_json
        bounded_json(data)
        atomic_write_json(self.user_file, data)

    def read_legacy(self):
        import msvcrt
        import stat
        from PYAS_PolicyNative import _pin_local_parents
        path, handles = _pin_local_parents(self.legacy_file)
        raw_handle = None
        try:
            raw_handle = _open(path, 0x80000000, 1, 0x00200000)
            attrs = (wt.DWORD * 2)()
            function = _kernel().GetFileInformationByHandleEx
            function.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]; function.restype = wt.BOOL
            if not function(raw_handle, 9, ctypes.byref(attrs), ctypes.sizeof(attrs)) or attrs[0] & 0x400:
                raise PolicyDenied('Legacy links are not trusted migration sources')
            fd = msvcrt.open_osfhandle(int(raw_handle), os.O_RDONLY | os.O_BINARY)
            raw_handle = None
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise PolicyDenied('Legacy migration requires a single regular file')
                raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES: raise PolicyDenied('Legacy configuration is too large')
            return raw
        finally:
            _close(raw_handle)
            for handle in reversed(handles): _close(handle)

    def read_policy(self):
        if not secure_path(self.root, True) or not secure_path(self.policy_file): return None
        try:
            with locked_read(self.policy_file) as stream: raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES: raise PolicyDenied('Policy document is too large')
            value = json.loads(raw.decode('utf-8'))
            if not isinstance(value, dict) or value.get('_format') != FORMAT: return None
            value['_revision'] = hashlib.sha256(raw).hexdigest()
            return value
        except (OSError, ValueError): return None

    def authorize(self, scope, revision, operation, initialize):
        lease = WindowsPolicyLease(self, scope, revision, operation, initialize)
        with self.lock: self.leases.add(lease)
        try: lease.start(); return lease
        except BaseException: lease.close(); raise

    def cancel(self):
        with self.lock: leases = list(self.leases)
        for lease in leases: lease.close()

    def pause(self, seconds=.05):
        lock = getattr(self.owner, 'lock_config', None)
        if lock is None: time.sleep(seconds)
        else:
            # Condition.wait releases all recursive RLock levels while waiting.
            condition = threading.Condition(lock)
            with condition: condition.wait(seconds)


class WindowsPolicyLease:
    def __init__(self, backend, scope, revision, operation, initialize):
        self.backend, self.scope, self.revision = backend, frozenset(scope), revision
        self.nonce = uuid4().hex
        self.header = dict(protocol=1, nonce=self.nonce, scope=sorted(scope), revision=revision,
            operation=str(operation)[:80], initialize=bool(initialize), pid=os.getpid())
        self.path = os.path.join(user_data_dir(), 'PolicyRequests', self.nonce + '.request')
        self.file = None; self.process = None; self.native_process = None
        self.authorized = False; self.committed = False; self.sent = False; self.closed = False
        self.launch_done = threading.Event(); self.launch_error = None

    def _open_channel(self):
        import msvcrt
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        handle = _open(self.path, 0xC0000000, 1, disposition=1)
        try: descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDWR | os.O_BINARY)
        except BaseException: _close(handle); raise
        try: self.file = os.fdopen(descriptor, 'r+b', buffering=0)
        except BaseException:
            os.close(descriptor)
            raise
        self.header['handle'] = int(msvcrt.get_osfhandle(self.file.fileno()))
        raw = bounded_json(self.header)
        self.file.write(struct.pack('<I', len(raw)) + raw)
        self.file.truncate(PAYLOAD_OFFSET + 4)
        self.file.seek(PAYLOAD_OFFSET); self.file.write(struct.pack('<I', 0)); self.file.flush()
        self.digest = hashlib.sha256(raw).hexdigest()

    def start(self):
        self._open_channel()
        admin = ctypes.WinDLL('shell32').IsUserAnAdmin
        admin.argtypes = []; admin.restype = wt.BOOL
        if admin():
            self.process = _run_broker(self.path, self.digest)
            self.launch_done.set()
        else:
            if not getattr(sys, 'frozen', False):
                raise PolicyDenied('Use an installed build, or run the development build as administrator')
            issue = installation_trust_issue()
            if issue:
                raise PolicyDenied('The authorization helper must be installed in an administrator-owned directory: ' + issue)
            threading.Thread(target=self._elevate, daemon=True, name='PYAS.PolicyAuthorization').start()
        deadline = time.monotonic() + 120
        ack = os.path.join(self.backend.root, '.auth-' + self.nonce + '.json')
        while time.monotonic() < deadline:
            if self.closed or getattr(self.backend.owner, 'closing', False): raise PolicyDenied('Authorization cancelled')
            if self.launch_done.is_set() and self.launch_error: raise PolicyDenied(str(self.launch_error))
            if secure_path(self.backend.root, True) and secure_path(ack):
                try:
                    with locked_read(ack) as stream: value = json.loads(stream.read(65536).decode('utf-8'))
                    if value.get('nonce') == self.nonce and value.get('stage') == 'ready':
                        self.authorized = True; return
                except (OSError, ValueError): pass
            if self._poll() is not None: raise PolicyDenied('Administrator authorization was declined or failed')
            self.backend.pause()
        raise PolicyDenied('Administrator authorization timed out')

    def _elevate(self):
        try:
            # Fixed executable and fixed helper verb; no caller-supplied code or output path.
            from PYAS_PolicyNative import elevate_helper
            self.native_process = elevate_helper(self.path, self.digest)
        except BaseException as error: self.launch_error = error
        finally:
            self.launch_done.set()
            if self.closed and self.native_process:
                _close(self.native_process); self.native_process = None

    def _poll(self):
        if self.process is not None: return self.process.poll()
        if self.native_process:
            from PYAS_PolicyNative import process_exit_code
            return process_exit_code(self.native_process)
        return None

    def commit(self, updates):
        if not self.authorized or self.closed or self.sent: raise PolicyDenied('Authorization is no longer valid')
        payload = bounded_json({'nonce': self.nonce, 'updates': updates})
        self.file.seek(PAYLOAD_OFFSET + 4); self.file.write(payload); self.file.flush(); os.fsync(self.file.fileno())
        self.file.seek(PAYLOAD_OFFSET); self.file.write(struct.pack('<I', len(payload))); self.file.flush(); os.fsync(self.file.fileno())
        self.sent = True
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            code = self._poll()
            if code is not None:
                document = self.backend.read_policy()
                if code != 0 and (not document or document.get('_request') != self.nonce):
                    raise PolicyDenied('Policy commit was rejected or conflicted')
                if not document or document.get('_request') != self.nonce: raise PolicyDenied('Policy commit could not be confirmed')
                self.committed = True
                return document
            self.backend.pause()
        raise PolicyPending('Policy commit result is unknown; do not repeat the action automatically')

    def close(self):
        if self.closed: return
        self.closed = True
        if self.file:
            if not self.sent:
                try:
                    self.file.seek(PAYLOAD_OFFSET); self.file.write(struct.pack('<I', 1)); self.file.flush()
                except OSError: pass
            self.file.close()
        if self.native_process: _close(self.native_process); self.native_process = None
        with self.backend.lock: self.backend.leases.discard(self)
        # The only removable path is this lease's own UUID file in its fixed folder.
        if os.path.dirname(self.path) == os.path.join(user_data_dir(), 'PolicyRequests') and os.path.basename(self.path) == self.nonce + '.request':
            try: os.unlink(self.path)
            except OSError: pass


def helper_main(arguments):
    if os.name != 'nt' or not getattr(sys, 'frozen', False) or len(arguments) != 2: return 2
    request, digest = arguments
    if len(digest) != 64 or any(ch not in '0123456789abcdef' for ch in digest): return 2
    try:
        from PYAS_PolicyNative import verify_request_owner
        handles = verify_request_owner(request, digest)
        try:
            process = _run_broker(request, digest)
            try: return process.wait(timeout=150)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
                return 4
        finally:
            for handle in reversed(handles): _close(handle)
    except Exception: return 3
