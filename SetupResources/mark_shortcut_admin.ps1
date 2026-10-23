# Marks .lnk shortcuts with SLDF_RUNAS_USER ("Run as administrator").
# Inno Setup's [Icons] has no elevation flag; the official ShellLink data-list
# COM interface is the supported way. Idempotent: sets the flag, keeps the rest.
param(
    [Parameter(Mandatory = $false)]
    [string[]]$ShortcutPath,
    # 无显式路径时扫描桌面与开始菜单(用户+公共),目标指向安装目录的
    # .lnk 一律打标 —— 快捷方式名称与位置随安装版本/机器而异
    [Parameter(Mandatory = $false)]
    [switch]$CommonLocations,
    [Parameter(Mandatory = $false)]
    [string]$InstallDir
)

$targets = @()

if ($ShortcutPath) {
    $targets += $ShortcutPath
}

if ($CommonLocations) {
    $shell = New-Object -ComObject WScript.Shell
    if (-not $InstallDir) {
        Write-Output 'InstallDir is required with -CommonLocations'
        exit 0
    }

    $roots = @(
        [Environment]::GetFolderPath('Desktop'),
        [Environment]::GetFolderPath('CommonDesktopDirectory'),
        (Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs'),
        (Join-Path ([Environment]::GetFolderPath('CommonStartMenu')) 'Programs')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    foreach ($root in $roots) {
        $links = Get-ChildItem -LiteralPath $root -Filter *.lnk -Recurse -ErrorAction SilentlyContinue

        foreach ($link in $links) {
            $target = ''

            try {
                $target = $shell.CreateShortcut($link.FullName).TargetPath
            } catch {
                continue
            }

            if ($target -and ($target -like ($InstallDir + '*'))) {
                $targets += $link.FullName
            }
        }
    }
}

if (-not $targets) {
    Write-Output 'no shortcut targets given'
    exit 0
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace PYAS.Setup {
    [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
    internal class CShellLink { }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("000214F9-0000-0000-C000-000000000046")]
    internal interface IShellLinkW {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszFile, int cch, IntPtr pfd, uint fFlags);
        void GetIDList(out IntPtr ppidl);
        void SetIDList(IntPtr pidl);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszName, int cch);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszDir, int cch);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszArgs, int cch);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
        short GetHotkey();
        void SetHotkey(short wHotkey);
        uint GetShowCmd();
        void SetShowCmd(uint iShowCmd);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszIconPath, int cch, out int piIcon);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, uint dwReserved);
        void Resolve(IntPtr hwnd, uint fFlags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
    }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("45E2B4AE-B1C3-11D0-B92F-00A0C90312E1")]
    internal interface IShellLinkDataList {
        void AddDataList(IntPtr pDataList);
        void CopyDataList(out IntPtr pDataList);
        void RemoveDataList(uint dwFlags);
        void GetFlags(out uint dwFlags);
        void SetFlags(uint dwFlags);
    }

    [ComImport, Guid("0000010B-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IPersistFile {
        void GetClassID(out Guid pClassID);
        void IsDirty();
        void Load([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, uint dwMode);
        void Save([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, bool fRemember);
        void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string pszFileName);
        void GetCurFile(out IntPtr ppszFileName);
    }

    public static class LinkElevator {
        private const uint SLDF_RUNAS_USER = 0x2000;

        // Windows PowerShell 5.1 的 Add-Type 是 C# 5 编译器:
        // 不支持 out 变量内联声明,先声明再传参
        public static uint GetFlags(string path) {
            IShellLinkW link = (IShellLinkW)(IPersistFile)Activator.CreateInstance(typeof(CShellLink));
            ((IPersistFile)link).Load(path, 0);
            IShellLinkDataList list = (IShellLinkDataList)link;
            uint flags;
            list.GetFlags(out flags);
            return flags;
        }

        public static void MarkRunAsAdmin(string path) {
            IShellLinkW link = (IShellLinkW)(IPersistFile)Activator.CreateInstance(typeof(CShellLink));
            IPersistFile persist = (IPersistFile)link;
            persist.Load(path, 0);
            IShellLinkDataList list = (IShellLinkDataList)link;
            uint flags;
            list.GetFlags(out flags);
            list.SetFlags(flags | SLDF_RUNAS_USER);
            persist.Save(path, true);
        }
    }
}
'@

$anyFailed = 0
foreach ($path in @($targets)) {
    $full = [Environment]::ExpandEnvironmentVariables($path)
    if (-not (Test-Path -LiteralPath $full)) {
        Write-Output "skip (missing): $full"
        continue
    }

    $failedNow = 0

    try {
        [PYAS.Setup.LinkElevator]::MarkRunAsAdmin($full)
        $flags = [PYAS.Setup.LinkElevator]::GetFlags($full)
        $marked = (($flags -band 0x2000) -ne 0)
        Write-Output ("marked={0}: {1}" -f $marked.ToString().ToLowerInvariant(), $full)
        if ($failedNow) { $anyFailed = 1 } else { $failedNow = 0 }
        if (-not $marked) { $anyFailed = 1 }
    } catch {
        Write-Output "failed: $full -> $($_.Exception.Message)"
        $anyFailed = 1
    }
}

if ($anyFailed) { exit 1 }

