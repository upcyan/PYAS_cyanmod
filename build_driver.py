"""构建内核过滤驱动 PYAS_Driver.sys(cl + link 直连,不依赖 VS 的 WDK 平台工具集)。

为什么不用 MSBuild:本机只装了 VS 的 WDK 组件缺失时,MSBuild 解析不到
`WindowsKernelModeDriver10.0` 工具集(MSB8020),而 WDK 的头文件与库其实已经齐了。
这里直接调 cl.exe / link.exe,参数对应 WDK 的 WDM 目标,产出可直接加载验证。

用法:
    python build_driver.py            # 编译并链接,产物 Output/PYAS_Driver.sys
    python build_driver.py --check    # 只编译不链接(快速查语法/类型)

依赖:Visual Studio(含 C++ 工具) + Windows Driver Kit(提供 km 头文件与 x64 库)。
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE_DIR = ROOT / "Plugins" / "Filter"
BUILD_DIR = ROOT / "build" / "driver"
OUTPUT_FILE = ROOT / "Output" / "PYAS_Driver.sys"

SOURCES = (
    "DriverEntry.cpp",
    "ProtectBoot.cpp",
    "ProtectFile.cpp",
    "ProtectMemory.cpp",
    "ProtectProcess.cpp",
    "ProtectRegistry.cpp",
    "ProtectRules.cpp",
)

# WDM 目标:内核模式、原生子系统。语法糖少一点,参数全部显式写出来便于排查。
COMPILE_FLAGS = (
    "/c", "/nologo", "/W3", "/utf-8",
    "/kernel",                 # 内核默认值:/GS-、/GR-、禁用异常处理语义
    "/D_AMD64_", "/D_WIN64", "/DNT=1", "/DDBG=0", "/D_WIN32_WINNT=0x0A00",
)

LINK_LIBRARIES = (
    "ntoskrnl.lib", "hal.lib", "wdm.lib", "fltmgr.lib",
    "bufferoverflowK.lib", "ntstrsafe.lib", "wdmsec.lib",
)


def find_vs_toolchain() -> tuple[Path, Path] | None:
    """返回 (cl.exe, link.exe);取已安装的最新 MSVC 版本。"""
    roots = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft Visual Studio",
    ]
    candidates: list[tuple[tuple[int, ...], Path]] = []

    for root in roots:
        for bin_dir in root.glob(r"*\*\VC\Tools\MSVC\*\bin\Hostx64\x64"):
            version = bin_dir.parents[3].name
            numbers = tuple(int(part) for part in version.split(".") if part.isdigit())
            candidates.append((numbers, bin_dir))

    for _, bin_dir in sorted(candidates, reverse=True):
        cl, link = bin_dir / "cl.exe", bin_dir / "link.exe"
        msvc_include = bin_dir.parents[2] / "include"
        if cl.is_file() and link.is_file() and msvc_include.is_dir():
            return cl, link, msvc_include

    return None


def find_wdk() -> tuple[list[Path], Path] | None:
    """返回 (头文件目录列表, x64 km 库目录);取最新 WDK 版本。"""
    kits = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits" / "10"
    versions = []

    for lib_dir in kits.glob(r"Lib\*\km\x64"):
        # Lib\<version>\km\x64 -> parents[1] 才是版本号
        version = lib_dir.parents[1].name
        include_root = kits / "Include" / version
        if (include_root / "km").is_dir() and (include_root / "shared").is_dir():
            versions.append((version, include_root, lib_dir))

    if not versions:
        return None

    _, include_root, lib_dir = sorted(versions)[-1]
    includes = [include_root / "km", include_root / "shared", include_root / "ucrt"]
    return includes, lib_dir


def run(command: list[str], label: str) -> bool:
    print(f"[{label}] {' '.join(str(part) for part in command[:3])} ...")
    proc = subprocess.run([str(part) for part in command], capture_output=True, text=True, errors="replace")

    if proc.stdout.strip():
        print(proc.stdout.strip())

    if proc.returncode != 0:
        if proc.stderr.strip():
            print(proc.stderr.strip(), file=sys.stderr)
        print(f"[失败] {label} 返回 {proc.returncode}", file=sys.stderr)
        return False

    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="构建 PYAS 内核驱动")
    parser.add_argument("--check", action="store_true", help="只编译不链接")
    args = parser.parse_args()

    toolchain = find_vs_toolchain()
    if not toolchain:
        print("未找到 MSVC(cl.exe/link.exe),请安装 Visual Studio C++ 生成工具", file=sys.stderr)
        return 1

    wdk = find_wdk()
    if not wdk:
        print("未找到 WDK 的 km 头文件/库,请安装 Windows Driver Kit", file=sys.stderr)
        return 1

    cl, link, msvc_include = toolchain
    includes, lib_dir = wdk
    # 内核头文件里会引用 <excpt.h> 这类 CRT 头,少这一条就是 C1083
    includes = [*includes, msvc_include]

    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR, ignore_errors=True)

    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    compile_command = [cl, *COMPILE_FLAGS, f"/Fo{BUILD_DIR}{os.sep}"]
    compile_command += [f"/I{path}" for path in includes]
    compile_command += [SOURCE_DIR / name for name in SOURCES]

    env_includes = ";".join(str(path) for path in includes)

    if not run(compile_command, "编译"):
        return 1

    if args.check:
        print("[完成] 仅编译通过")
        return 0

    objects = sorted(glob.glob(str(BUILD_DIR / "*.obj")))
    if not objects:
        print("没有生成任何 obj", file=sys.stderr)
        return 1

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    link_command = [
        link, "/NOLOGO", "/DRIVER", "/SUBSYSTEM:NATIVE", "/ENTRY:GsDriverEntry",
        f"/OUT:{OUTPUT_FILE}", *objects, f"/LIBPATH:{lib_dir}", *LINK_LIBRARIES,
    ]

    if not run(link_command, "链接"):
        return 1

    size = OUTPUT_FILE.stat().st_size
    print(f"[完成] {OUTPUT_FILE} ({size / 1024:.1f} KiB)")
    print(f"[提示] 头文件: {env_includes}")
    print("[提示] 未签名驱动无法在常规系统加载,需 signtool 签名 + 测试签名模式或正式证书")
    return 0


if __name__ == "__main__":
    sys.exit(main())
