# -*- coding: utf-8 -*-
"""跨平台构建驱动:在 Linux 宿主机执行 build.py/build_menu.py 里所有纯 Python 步骤。

前提(由容器/手工完成):
  - dist/PYAS.exe           wine + Windows Python + PyInstaller 产物
  - MenuPackage/PYAS_Menu.exe  mingw-w64 编译产物
  - Output/PYAS_Menu_v{ver}.msix  wine makeappx + signtool 签名产物
  - Output/menu_cert.cer    openssl 生成(已就位)
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import build
import build_menu as bm


def main():
    stage = sys.argv[1] if len(sys.argv) > 1 else "--late"
    version_dot = bm.read_version()  # 3.7.0.19
    print(f"[驱动] 版本 {version_dot} 阶段 {stage}")

    if stage == "--early":
        # 1) 菜单包资源:manifest(注入版本)+ Assets/icon.png(需要 PIL)
        bm.build_assets()

        # 2) 生成 register/unregister/trust 脚本(内嵌证书哈希与 msix 文件名)
        msix_name = f"PYAS_Menu_v{version_dot}.msix"
        bm.write_scripts(version_dot, msix_name)

        # 5) makeappx 的映射文件(wine 视角:/repo → Z:\repo)
        def zpath(p):
            return "Z:\\" + str(p.resolve()).lstrip("/").replace("/", "\\")

        manifest_src = ROOT / "MenuPackage" / "AppxManifest.xml"
        icon_src = ROOT / "MenuPackage" / "Assets" / "icon.png"
        mapping = ROOT / "MenuPackage" / "_mapping.txt"
        mapping.write_text(
            "[Files]\n"
            f'"{zpath(manifest_src)}" "AppxManifest.xml"\n'
            f'"{zpath(icon_src)}" "Assets/icon.png"\n',
            encoding="utf-8")
        print(f"[驱动] 映射文件已写: {mapping}")
    else:
        # 3) 组装 Payload(PYAS.exe + Engine/Interface/Plugins + License)
        build.assemble_payload()

        # 4) 菜单材料进 Payload(exe + msix + cer + 三个 ps1)
        bm.deploy_payload(version_dot)

        # 6) Redist 就位(已在 /tools/downloads 下载,拷贝即可)
        build.REDIST_DIR.mkdir(exist_ok=True)
        for src, dst in (
            ("/vol1/@appdata/zcode/pyas-build-tools/downloads/VC_redist.x64.exe", "VC_redist.x64.exe"),
            ("/vol1/@appdata/zcode/pyas-build-tools/downloads/MicrosoftEdgeWebview2Setup.exe", "MicrosoftEdgeWebview2Setup.exe"),
        ):
            target = build.REDIST_DIR / dst
            if not (target.is_file() and target.stat().st_size > 1024 * 1024):
                shutil.copyfile(src, target)
            build.log("资源", f"{dst} 就位")

    print("[驱动] 宿主机步骤完成")


if __name__ == "__main__":
    main()
