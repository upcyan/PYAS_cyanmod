# Marks .lnk shortcuts with SLDF_RUNAS_USER ("Run as administrator").
# Inno Setup's [Icons] has no elevation flag; the official ShellLink data-list
# COM interface is the supported way. Idempotent: sets the flag, keeps the rest.
param(
    [Parameter(Mandatory = $true)]
    [string[]]$ShortcutPath
)

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

foreach ($path in $ShortcutPath) {
    $full = [Environment]::ExpandEnvironmentVariables($path)
    if (-not (Test-Path -LiteralPath $full)) {
        Write-Output "skip (missing): $full"
        continue
    }

    try {
        [PYAS.Setup.LinkElevator]::MarkRunAsAdmin($full)
        $flags = [PYAS.Setup.LinkElevator]::GetFlags($full)
        $marked = (($flags -band 0x2000) -ne 0)
        Write-Output ("marked={0}: {1}" -f $marked.ToString().ToLowerInvariant(), $full)
        if (-not $marked) { exit 1 }
    } catch {
        Write-Output "failed: $full -> $($_.Exception.Message)"
        exit 1
    }
}
