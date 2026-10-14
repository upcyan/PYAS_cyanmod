# -*- coding: utf-8 -*-
"""纯 Python 的稀疏 msix 打包器(替代 wine 下静默失败的 makeappx)。

包结构:zip 内 [Content_Types].xml 必须是首个条目且不压缩;
AppxBlockMap 覆盖除自身与签名外的所有条目,块哈希 = 未压缩数据按 64KB
分块的 SHA-256(base64);File@Size=压缩后尺寸,LfSize=原始尺寸。
签名由 wine signtool 在本脚本之后执行。
"""
import base64
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

CHUNK = 65536
BLOCKMAP_NAME = "AppxBlockMap.xml"
CONTENT_TYPES_NAME = "[Content_Types].xml"

CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="png" ContentType="image/png"/>'
    '<Override PartName="/AppxManifest.xml" '
    'ContentType="application/vnd.ms-appx.manifest+xml"/>'
    "</Types>"
)


def block_entries(data):
    """未压缩数据的 64KB 分块哈希列表,末块带 Size 属性。"""
    entries = []

    for offset in range(0, len(data), CHUNK):
        chunk = data[offset:offset + CHUNK]
        hash_value = base64.b64encode(hashlib.sha256(chunk).digest()).decode("ascii")

        if len(chunk) == CHUNK:
            entries.append(f'<Block Hash="{hash_value}"/>')
        else:
            entries.append(f'<Block Hash="{hash_value}" Size="{len(chunk)}"/>')

    return entries


def build_blockmap(parts):
    """parts: [(zip 内路径, 压缩后尺寸, 原始字节)] → BlockMap XML 文本。"""
    files = []

    for name, compressed_size, raw in parts:
        blocks = "".join(block_entries(raw))
        files.append(
            f'<File Name="{name}" Size="{compressed_size}" LfSize="{len(raw)}">{blocks}</File>'
        )

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\r\n'
        '<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
        'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">'
        + "".join(files)
        + "</BlockMap>"
    )


def pack(manifest_path, icon_path, output_path):
    manifest = Path(manifest_path).read_bytes()
    icon = Path(icon_path).read_bytes()

    # 第一遍:确定各条目的压缩后尺寸(内容确定 → deflate 结果确定)
    probe = io.BytesIO()
    parts = []
    with zipfile.ZipFile(probe, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(_info(CONTENT_TYPES_NAME, stored=True), CONTENT_TYPES)
        archive.writestr(_info("AppxManifest.xml"), manifest)
        archive.writestr(_info("Assets/icon.png"), icon)
        for info in archive.infolist():
            raw = {
                CONTENT_TYPES_NAME: CONTENT_TYPES.encode("utf-8"),
                "AppxManifest.xml": manifest,
                "Assets/icon.png": icon,
            }[info.filename]
            parts.append((info.filename, info.compress_size, raw))

    blockmap = build_blockmap(parts).encode("utf-8")

    # 第二遍:写入最终包([Content_Types].xml 首位,BlockMap 最后)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(_info(CONTENT_TYPES_NAME, stored=True), CONTENT_TYPES)
        archive.writestr(_info("AppxManifest.xml"), manifest)
        archive.writestr(_info("Assets/icon.png"), icon)
        archive.writestr(_info(BLOCKMAP_NAME), blockmap)

    print(f"[msix] {output} ({output.stat().st_size} bytes, "
        f"{len(parts)} parts + blockmap)")


def _info(name, stored=False):
    info = zipfile.ZipInfo(name, date_time=(2026, 10, 11, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    return info


if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    version = (root / "PYAS_Version.py").read_text(encoding="utf-8")
    import re
    match = re.search(r'VERSION\s*=\s*"([^"]+)"', version)
    numeric = match.group(1).replace("-", ".")
    pack(root / "MenuPackage" / "AppxManifest.xml",
        root / "MenuPackage" / "Assets" / "icon.png",
        root / "Output" / f"PYAS_Menu_v{numeric}.msix")
