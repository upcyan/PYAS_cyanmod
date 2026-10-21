# -*- coding: utf-8 -*-
"""构建 PYAS 右键菜单 sparse package。

流程:MSVC 编译 PYAS_Menu.exe -> 生成 manifest/Assets -> makeappx 打包
     -> 自签证书(首次自动创建)签名 -> Output/PYAS_Menu.msix + 注册/卸载脚本。

注册测试(需管理员):
    powershell -ExecutionPolicy Bypass -File Output\\register_menu.ps1 -ExternalLocation "E:\\...\\Payload"
公开发布部署:安装器以管理员在安装完成后自动运行同样命令(ExternalLocation=安装目录)。
"""
import io
import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# 同 build.py:放宽控制台编码错误,避免英文代码页下中文日志直接崩溃。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = Path(__file__).resolve().parent
VSWHERE = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
SDK_BIN = Path(r"C:\Program Files (x86)\Windows Kits\10\bin")
SDK_INCLUDE = Path(r"C:\Program Files (x86)\Windows Kits\10\Include")
SDK_LIB = Path(r"C:\Program Files (x86)\Windows Kits\10\Lib")
CPP = ROOT / "Plugins" / "MenuServer"
STAGE = ROOT / "MenuPackage"
OUT = ROOT / "Output"
BUILD = ROOT / "build" / "menu"
CERT_SUBJECT = "CN=PYAS Cyanmod Menu"
CERT_PFX = BUILD / "menu_cert.pfx"
CERT_CER = OUT / "menu_cert.cer"
CERT_PWD = "PYAS-Menu-Local"
POWERSHELL_UTF8 = '''[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
'''


def run_powershell(script, timeout=60):
    # -EncodedCommand preserves quotes and paths containing spaces when called
    # by Python's Windows command-line encoder.
    encoded = base64.b64encode((POWERSHELL_UTF8 + script).encode('utf-16-le')).decode('ascii')
    environment = os.environ.copy()
    environment['PSModulePath'] = os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'),
        'System32', 'WindowsPowerShell', 'v1.0', 'Modules')
    return subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-OutputFormat', 'Text', '-EncodedCommand', encoded],
        capture_output=True, text=True, encoding='utf-8-sig', timeout=timeout, env=environment)


def die(msg, hint=None):
    print(f"[失败] {msg}")
    if hint:
        print(f"       {hint}")
    sys.exit(1)


def read_version():
    import re
    text = (ROOT / "PYAS_Version.py").read_text(encoding="utf-8")
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        die("PYAS_Version.py 缺少 VERSION")
    return m.group(1).replace("-", ".")


def find_msvc():
    if not VSWHERE.exists():
        die("未找到 vswhere", "请安装 Visual Studio 2026(含 C++ 桌面开发)")
    result = subprocess.run([str(VSWHERE), "-latest", "-property", "installationPath"],
                            capture_output=True, text=True)
    vs = (result.stdout or "").strip().splitlines()
    if not vs:
        die("vswhere 未返回 VS 路径")
    msvc_root = Path(vs[0]) / "VC" / "Tools" / "MSVC"
    versions = sorted((p for p in msvc_root.iterdir() if p.is_dir()),
                      key=lambda p: [int(x) for x in p.name.split(".")])
    if not versions:
        die("未找到 MSVC 工具集")
    latest = versions[-1]
    cl = latest / "bin" / "Hostx64" / "x64" / "cl.exe"
    if not cl.exists():
        die("未找到 cl.exe", "请安装『使用 C++ 的桌面开发』工作负载")
    return cl, latest


def find_sdk_tools():
    if not SDK_BIN.exists():
        die("未找到 Windows SDK")
    def _sdk_key(p):
        try:
            return [int(x) for x in p.name.split(".")]
        except ValueError:
            return []
    versions = sorted((p for p in SDK_BIN.iterdir() if p.is_dir() and _sdk_key(p)),
                      key=_sdk_key)
    latest = versions[-1] / "x64"
    signtool = latest / "signtool.exe"
    makeappx = latest / "makeappx.exe"
    if not signtool.exists() or not makeappx.exists():
        die("SDK 缺少 signtool/makeappx")
    include_root = SDK_INCLUDE / versions[-1].name
    lib_root = SDK_LIB / versions[-1].name
    return signtool, makeappx, include_root, lib_root


def compile_exe(cl, msvc_root, include_root, lib_root):
    out_exe = STAGE / "PYAS_Menu.exe"
    STAGE.mkdir(parents=True, exist_ok=True)
    include_um = include_root / "um"
    include_shared = include_root / "shared"
    result = subprocess.run(
        [
            str(cl), "/nologo", "/O2", "/W3", "/EHsc",
            "/DUNICODE", "/D_UNICODE",
            f"/I{include_um}", f"/I{include_shared}", f"/I{include_root / 'ucrt'}", f"/I{msvc_root / 'include'}",
            "/utf-8",
            str(CPP / "PYAS_Menu.cpp"),
            f"/Fe:{out_exe}", f"/Fo:{STAGE / 'PYAS_Menu.obj'}",
            "ole32.lib", "shell32.lib", "shlwapi.lib", "user32.lib", "uuid.lib",
            "/link", f"/LIBPATH:{msvc_root / 'lib' / 'x64'}", f"/LIBPATH:{lib_root / 'um' / 'x64'}", f"/LIBPATH:{lib_root / 'ucrt' / 'x64'}", "/SUBSYSTEM:WINDOWS", "/ENTRY:wmainCRTStartup",
        ],
        capture_output=True, text=True, encoding="gbk", errors="replace",
    )
    if result.returncode != 0 or not out_exe.exists():
        print(result.stdout[-4000:])
        print(result.stderr[-2000:])
        die("PYAS_Menu.exe 编译失败")
    print(f"[构建] PYAS_Menu.exe 完成({out_exe.stat().st_size / 1024:.0f} KB)")
    return out_exe


def build_assets():
    assets = STAGE / "Assets"
    assets.mkdir(parents=True, exist_ok=True)
    png = assets / "icon.png"

    from PIL import Image
    icon = Image.open(ROOT / "Interface" / "static" / "img" / "icon.ico")
    image = Image.new("RGB", (150, 150), (245, 245, 247))
    resized = icon.resize((134, 134))
    image.paste(resized, (8, 8), resized)
    image.save(png, "PNG")

    manifest = (CPP / "AppxManifest.template.xml").read_text(encoding="utf-8")
    version = read_version()
    manifest = manifest.replace("{VERSION}", version)
    (STAGE / "AppxManifest.xml").write_text(manifest, encoding="utf-8")
    print(f"[资源] manifest/Assets 已生成(包版本 {version})")
    return version


def cert_is_usable():
    """pfx 存在且非空才算可复用 —— 构建会清 build/,0 字节残留不能当证书。"""
    try:
        return CERT_PFX.is_file() and CERT_PFX.stat().st_size > 512
    except OSError:
        return False


def ensure_cert(force=False):
    CERT_PFX.parent.mkdir(parents=True, exist_ok=True)

    if not force and cert_is_usable():
        print("[证书] 复用已有自签证书")
        return

    if CERT_PFX.exists():
        CERT_PFX.unlink()
        print("[证书] 旧证书不可用,重新生成")
    ps = f'''
$cert = New-SelfSignedCertificate -Type Custom -Subject "{CERT_SUBJECT}" `
    -KeyUsage DigitalSignature -FriendlyName "PYAS Menu Signing" `
    -CertStoreLocation "Cert:\\CurrentUser\\My" `
    -TextExtension @("2.5.29.37={{text}}1.3.6.1.5.5.7.3.3", "2.5.29.19={{text}}")
$menuSigningPassword = ConvertTo-SecureString -String "{CERT_PWD}" -Force -AsPlainText
Export-PfxCertificate -Cert ("Cert:\\CurrentUser\\My\\" + $cert.Thumbprint) `
    -FilePath "{CERT_PFX}" -Password $menuSigningPassword | Out-Null
Write-Output $cert.Thumbprint
'''
    result = run_powershell(ps, timeout=120)
    if not CERT_PFX.exists():
        die("自签证书创建失败", (result.stdout or "")[-500:] + (result.stderr or "")[-500:])
    print("[证书] 自签证书已创建")


def pack_and_sign(version, makeappx, signtool):
    msix = OUT / f"PYAS_Menu_v{version}.msix"
    if msix.exists():
        msix.unlink()
    mapping = STAGE / "_mapping.txt"
    manifest_src = str((STAGE / "AppxManifest.xml").resolve())
    icon_src = str((STAGE / "Assets" / "icon.png").resolve())
    # 真 sparse 包:只有 manifest 和图标入包,PYAS_Menu.exe 留在应用目录
    # (通过 Add-AppxPackage -ExternalLocation 指向),COM 服务器从外置位置
    # 运行,GetModuleFileNameW 推算出的同目录 PYAS.exe 路径才正确。
    mapping.write_text(
        "[Files]\n"
        '"' + manifest_src + '" "AppxManifest.xml"\n'
        '"' + icon_src + '" "Assets/icon.png"\n',
        encoding="utf-8")
    result = subprocess.run([str(makeappx), "pack", "/f", str(mapping), "/nv", "/p", str(msix), "/o"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print((result.stdout or "")[-2000:], (result.stderr or "")[-1000:])
        die("makeappx 打包失败")
    ensure_cert()
    result = subprocess.run(
        [str(signtool), "sign", "/fd", "SHA256", "/f", str(CERT_PFX), "/p", f"{CERT_PWD}", str(msix)],
        capture_output=True, text=True)
    if result.returncode != 0:
        print((result.stdout or "")[-2000:], (result.stderr or "")[-1000:])
        die("签名失败")
    print(f"[打包] {msix.name} 已签名")

    # 导出公钥证书(注册时导入 TrustedPeople)
    ps = f'''
$ErrorActionPreference = 'Stop'
try {{
$menuSigningPassword = ConvertTo-SecureString -String "{CERT_PWD}" -Force -AsPlainText
$cert = (Get-PfxData -FilePath "{CERT_PFX}" -Password $menuSigningPassword).EndEntityCertificates[0]
[System.IO.File]::WriteAllBytes("{CERT_CER}", $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
}} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}
'''
    exported = run_powershell(ps)

    if exported.returncode != 0 or not CERT_CER.is_file():
        # build/ 被清掉后 pfx 可能已不在:重建一次再导,别让整包构建失败
        print('[证书] 导出失败,重建证书后重试')
        ensure_cert(force=True)
        exported = run_powershell(ps)

        if exported.returncode != 0 or not CERT_CER.is_file():
            die('菜单签名公钥证书导出失败', (exported.stderr or '')[:500])
    print("[证书] 公钥证书已导出:", CERT_CER.name)
    return msix


def write_scripts(version, msix_name):
    register = OUT / "register_menu.ps1"
    unregister = OUT / "unregister_menu.ps1"
    certificate_hash = hashlib.sha256(CERT_CER.read_bytes()).hexdigest().upper()
    trust = OUT / 'trust_menu.ps1'
    trust.write_text(f'''param([switch]$RespectConfig)
{POWERSHELL_UTF8}
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$env:PSModulePath = "$PSHOME\\Modules;$env:ProgramFiles\\WindowsPowerShell\\Modules"
if ([Environment]::OSVersion.Version.Build -lt 22000) {{ return }}
if ($RespectConfig) {{
    $configFile = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "PYAS.Policy\\Config.json"
    if (Test-Path -LiteralPath $configFile) {{
        $config = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
        if ($config.context_switch -eq $false) {{ return }}
    }}
}}
$certificateFile = Join-Path $PSScriptRoot "menu_cert.cer"
if ((Get-FileHash -LiteralPath $certificateFile -Algorithm SHA256).Hash -ne "{certificate_hash}") {{
    throw "Menu signing certificate fingerprint mismatch; trust was not changed."
}}
$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificateFile)
if ($certificate.Subject -ne "{CERT_SUBJECT}" -or
    $certificate.NotBefore -gt (Get-Date) -or $certificate.NotAfter -lt (Get-Date)) {{
    throw "Menu signing certificate identity or validity is invalid."
}}
$eku = @($certificate.Extensions | Where-Object {{ $_.Oid.Value -eq "2.5.29.37" }})
$usage = @($eku.EnhancedKeyUsages)
if ($usage.Count -ne 1 -or $usage[0].Value -ne "1.3.6.1.5.5.7.3.3") {{
    throw "Menu certificate must be limited to code signing."
}}
$storePath = "Cert:\\LocalMachine\\TrustedPeople\\" + $certificate.Thumbprint
if (Test-Path -LiteralPath $storePath) {{ return }}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    throw "The menu certificate is not trusted by this computer. Run the PYAS installer as administrator to repair menu registration."
}}
Import-Certificate -FilePath $certificateFile -CertStoreLocation Cert:\\LocalMachine\\TrustedPeople | Out-Null
if (-not (Test-Path -LiteralPath $storePath)) {{ throw "Machine menu certificate trust verification failed." }}
Write-Output "PYAS menu signing certificate trusted in LocalMachine TrustedPeople."
''', encoding='utf-8-sig')
    register.write_text(f'''# Register for the interactive user, not all users or the elevated installer account.
param(
    [Parameter(Mandatory=$true)][string]$ExternalLocation,
    [string]$Msix,
    [string]$Cer,
    [switch]$RespectConfig
)
{POWERSHELL_UTF8}
$ErrorActionPreference = "Stop"
if (-not $Msix) {{ $Msix = Join-Path $PSScriptRoot "{msix_name}" }}
if (-not $Cer) {{ $Cer = Join-Path $PSScriptRoot "menu_cert.cer" }}
$env:PSModulePath = "$PSHOME\\Modules;$env:ProgramFiles\\WindowsPowerShell\\Modules"
if ([Environment]::OSVersion.Version.Build -lt 22000) {{ exit 0 }}
$ExternalLocation = (Resolve-Path -LiteralPath $ExternalLocation).Path
if (-not (Test-Path -LiteralPath (Join-Path $ExternalLocation "PYAS_Menu.exe")) -or
    -not (Test-Path -LiteralPath (Join-Path $ExternalLocation "PYAS.exe"))) {{ throw "Menu executables are missing" }}
if ($RespectConfig) {{
    $configFile = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "PYAS.Policy\\Config.json"
    if (-not (Test-Path -LiteralPath $configFile)) {{ return }}
    if (Test-Path -LiteralPath $configFile) {{
        $config = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
        if ($config.context_switch -eq $false) {{
            & (Join-Path $PSScriptRoot "unregister_menu.ps1")
            exit 0
        }}
    }}
}}
$stateDirectory = Join-Path $env:LOCALAPPDATA "PYAS\\Menu"
$stateFile = Join-Path $stateDirectory "registration.json"
$packageHash = (Get-FileHash -LiteralPath $Msix -Algorithm SHA256).Hash
$existing = Get-AppxPackage -Name "PYAS-Cyanmod-Menu"
if ($existing -and (Test-Path -LiteralPath $stateFile)) {{
    try {{
        $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
        if (($state.path -eq $ExternalLocation) -and ($state.hash -eq $packageHash)) {{ exit 0 }}
    }} catch {{ }}
}}
& (Join-Path $PSScriptRoot "trust_menu.ps1")
if ($existing) {{ $existing | Remove-AppxPackage -ErrorAction Stop }}
Add-AppxPackage -Path $Msix -ExternalLocation $ExternalLocation -ErrorAction Stop
if (-not (Get-AppxPackage -Name "PYAS-Cyanmod-Menu")) {{ throw "Package registration verification failed" }}
New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
@{{ path = $ExternalLocation; hash = $packageHash }} | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8
Write-Output "Modern context menu registered for the current user. Explorer may need to be reopened."
''', encoding="utf-8-sig")
    unregister.write_text(POWERSHELL_UTF8 + '''$ErrorActionPreference = "Stop"
$env:PSModulePath = "$PSHOME\\Modules;$env:ProgramFiles\\WindowsPowerShell\\Modules"
Get-AppxPackage -Name "PYAS-Cyanmod-Menu" | ForEach-Object {
    Remove-AppxPackage -Package $_.PackageFullName -ErrorAction Stop
}
$stateFile = Join-Path $env:LOCALAPPDATA "PYAS\\Menu\\registration.json"
if (Test-Path -LiteralPath $stateFile) { Remove-Item -LiteralPath $stateFile -Force }
Write-Output "Modern context menu unregistered for the current user."
''', encoding="utf-8-sig")
    print("[脚本] register_menu.ps1 / unregister_menu.ps1 已生成(UTF-8 BOM)")


def deploy_payload(version):
    """把菜单 exe 与注册材料放进 Payload,供本机测试与安装器打包。"""
    exe_src = STAGE / "PYAS_Menu.exe"
    if not exe_src.exists():
        die("找不到编译产物 PYAS_Menu.exe")

    shutil.copy2(exe_src, ROOT / "Payload" / "PYAS_Menu.exe")
    menu_dir = ROOT / "Payload" / "Menu"
    menu_dir.mkdir(exist_ok=True)
    shutil.copy2(OUT / f"PYAS_Menu_v{version}.msix", menu_dir / f"PYAS_Menu_v{version}.msix")
    shutil.copy2(OUT / "menu_cert.cer", menu_dir / "menu_cert.cer")
    shutil.copy2(OUT / "register_menu.ps1", menu_dir / "register_menu.ps1")
    shutil.copy2(OUT / "unregister_menu.ps1", menu_dir / "unregister_menu.ps1")
    shutil.copy2(OUT / "trust_menu.ps1", menu_dir / "trust_menu.ps1")
    print("[部署] Payload/PYAS_Menu.exe 与 Payload/Menu/ 已更新")


def main():
    version = read_version()
    cl, msvc_root = find_msvc()
    signtool, makeappx, include_root, lib_root = find_sdk_tools()
    print(f"[环境] MSVC {msvc_root.name} | SDK {include_root.name}")
    compile_exe(cl, msvc_root, include_root, lib_root)
    build_assets()
    ensure_cert()
    msix = pack_and_sign(version, makeappx, signtool)
    write_scripts(version, msix.name)
    deploy_payload(version)
    print(f"\n[完成] 安装包目录: {OUT}")
    print("注册测试(管理员 PowerShell):")
    print(f'  powershell -ExecutionPolicy Bypass -File "{OUT / "register_menu.ps1"}" -ExternalLocation "<安装目录>"')


if __name__ == "__main__":
    main()
