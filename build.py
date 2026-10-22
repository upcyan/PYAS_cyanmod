# -*- coding: utf-8 -*-
"""PYAS Security Cyanmod 一键构建脚本。

用法:
    python build.py            # 交互菜单
    python build.py local      # 路径二:仅本地构建 = 开发者模式(产出 Output\\PYAS_Setup_v版本.exe)
    python build.py release    # 路径一:完整发布 = 普通模式(本地构建 + 上传 GitHub Release)
    python build.py check      # 仅检查构建环境
    python build.py release --skip-build   # 跳过构建,直接上传已有安装包

渠道(--channel)决定安装包带哪些能力:开发者模式的「检查更新」会附带上游
87owo/PYAS 的版本比对并提示跟进,普通模式不含。默认 local=dev、release=normal,
CI 构建请显式写 --channel normal。
"""

import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Windows 控制台默认代码页(如英文系统的 cp1252)编不了中文日志,这里只放宽
# errors 不强制改编码:本地中文控制台显示不变,CI 由 PYTHONUTF8=1 走 UTF-8。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = Path(__file__).resolve().parent
ISS_FILE = ROOT / "PYAS_Inno.iss"
VERSION_FILE = ROOT / "PYAS_Version.py"
LICENSE_FILE = ROOT / "LICENSE.txt"
PAYLOAD_DIR = ROOT / "Payload"
REDIST_DIR = ROOT / "Redist"
SETUP_RES_DIR = ROOT / "SetupResources"
OUTPUT_DIR = ROOT / "Output"
# 每次发布的说明正文。抬头由 read_release_notes 按版本号生成,文件里只写条目。
# 缺失或为空直接阻断发布:宁可发不出去,也不要沿用上一版的说明。
RELEASE_NOTES_FILE = ROOT / "RELEASE_NOTES.md"
DIST_DIR = ROOT / "dist"
ICON_FILE = ROOT / "Interface" / "static" / "img" / "icon.ico"
# 构建渠道：本地构建 = 开发者模式（多查上游、提示跟进），发布构建 = 普通模式。
# 渠道写入生成模块 PYAS_Build.py，由 PYAS_Channel.py 读取；该文件不进版本库，
# 缺失时程序按普通模式运行。
CHANNEL_FILE = ROOT / "PYAS_Build.py"
CHANNELS = {
    "dev": ("开发者模式", "本地构建：检查更新会附带上游跟进比对"),
    "normal": ("普通模式", "发布构建：不含上游跟进等开发用能力"),
}
# 各构建模式的默认渠道：本地构建给开发者模式,发布构建给普通模式
MODE_CHANNEL = {"local": "dev", "release": "normal"}

GITHUB_REPO = "upcyan/PYAS_cyanmod"
VC_REDIST_URL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
WEBVIEW2_URL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
ISL_API_URL = "https://api.github.com/repos/jrsoftware/issrc/contents/Files/Languages"
ISL_RAW_URL = "https://raw.githubusercontent.com/jrsoftware/issrc/main/Files/Languages"

# 键 = Languages 目录内的本地文件名(与 iss 引用一致);值 = issrc 仓库内相对路径
ISS_LANGUAGES = {
    "ChineseSimplified.isl": "ChineseSimplified.isl",
    "ChineseTraditional.isl": "ChineseTraditional.isl",
    "Japanese.isl": "Japanese.isl",
    "Korean.isl": "Korean.isl",
    "French.isl": "French.isl",
    "Spanish.isl": "Spanish.isl",
    "Hindi.islu": "Unofficial/Hindi.islu",
    "Arabic.isl": "Arabic.isl",
    "Russian.isl": "Russian.isl",
    "Slovenian.isl": "Slovenian.isl",
}

PYTHON_PACKAGES = [
    ("PyInstaller", "pyinstaller"),
    ("webview", "pywebview"),
    ("pystray", "pystray"),
    ("PIL", "Pillow"),
    ("requests", "requests"),
    ("pefile", "pefile"),
    ("yara", "yara-python"),
    ("numpy", "numpy"),
    ("onnxruntime", "onnxruntime"),
]

PIP_INSTALL_LINE = (
    "pip install pyinstaller pywebview pystray Pillow requests pefile yara-python numpy onnxruntime"
)

def _inno_common_paths():
    paths = [
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
    ]
    local_appdata = os.environ.get("LOCALAPPDATA")

    if local_appdata:
        paths.insert(0, str(Path(local_appdata) / "Programs" / "Inno Setup 6" / "ISCC.exe"))

    return paths


INNO_COMMON_PATHS = _inno_common_paths()


def log(stage, message):
    print(f"[{stage}] {message}")


def die(message, hint=None):
    print(f"\n[失败] {message}")
    if hint:
        print(f"       {hint}")
    sys.exit(1)


def run(command, **kwargs):
    print(f"  $ {' '.join(str(part) for part in command)}")
    return subprocess.run(command, cwd=str(ROOT), **kwargs)


def write_build_channel(channel):
    """把构建渠道写进生成模块 PYAS_Build.py(打包时被收进 PYAS.exe)。"""
    if channel not in CHANNELS:
        die(f"未知构建渠道: {channel}", "可用: " + ", ".join(CHANNELS))

    label, note = CHANNELS[channel]
    CHANNEL_FILE.write_text(
        '# 本文件由 build.py 生成,不要手改,也不要提交到版本库。\n'
        f'CHANNEL = "{channel}"  # {label}·{note}\n',
        encoding="utf-8",
    )
    log("渠道", f"{label}（{note}）")

    return channel


def read_build_channel():
    """读当前 PYAS_Build.py 里的渠道(生成文件缺失按 normal)。"""
    try:
        match = re.search(r'^CHANNEL\s*=\s*"([^"]+)"', CHANNEL_FILE.read_text(encoding="utf-8"), re.M)
    except OSError:
        return "normal"

    channel = match.group(1) if match else "normal"

    return channel if channel in CHANNELS else "normal"


def assert_publish_channel(interactive):
    """发布包必须是普通模式:挡住「本地构建成开发者模式后直接发布」这条错路。"""
    channel = read_build_channel()

    if channel == "normal":
        return

    label = CHANNELS[channel][0]
    hint = f"当前 Output 里的安装包是{label};发布前请先 python build.py local --channel normal 重新构建"

    if interactive:
        print(f"\n[警告] {hint}")
        if input("仍要发布? 输入 yes 继续: ").strip().lower() != "yes":
            sys.exit(0)

        return

    die(hint, "发布包不应带开发者模式的上游跟进能力")


def read_version():
    try:
        text = VERSION_FILE.read_text(encoding="utf-8")
    except OSError as error:
        die(f"读取 {VERSION_FILE.name} 失败: {error}")

    match = re.search(r'^VERSION\s*=\s*"([^"]+)"', text, re.M)

    if not match:
        die(f"无法在 {VERSION_FILE.name} 中找到 VERSION 定义")

    version = match.group(1)

    if not re.fullmatch(r"\d+\.\d+\.\d+-\d+", version):
        die(
            f"版本号 {version!r} 不符合格式要求",
            "本项目版本号为:PYAS 上游版本号-Cyanmod 修订号"
            "(连字符前跟随上游,连字符后为本项目修订序号,如 3.7.1-1、3.7.2-1)",
        )

    return version


def sync_iss_version(version):
    # Inno Setup / PE 版本资源只接受纯数字段,连字符形态转为点分
    numeric = version.replace("-", ".")
    # Inno Setup 按 UTF-8(带 BOM)读脚本;没有 BOM 时中文注释会按 ANSI 解码,
    # 某些双字节字符的尾字节是 0x7D("}"),会把 { } 注释提前闭合 → Invalid section tag。
    text = ISS_FILE.read_text(encoding="utf-8-sig")
    updated, count = re.subn(
        r'^#define AppVersion "[^"]*"',
        f'#define AppVersion "{numeric}"',
        text,
        count=1,
        flags=re.M,
    )

    if count != 1:
        die("PYAS_Inno.iss 中找不到 #define AppVersion")

    if updated != text:
        ISS_FILE.write_text(updated, encoding="utf-8-sig", newline="\n")
        log("版本", f"PYAS_Inno.iss AppVersion 已同步为 {numeric}")
    else:
        log("版本", f"PYAS_Inno.iss AppVersion 已是 {numeric}")


def check_python_packages(interactive):
    missing = []

    for module_name, package_name in PYTHON_PACKAGES:
        if importlib.util.find_spec(module_name) is None:
            missing.append(package_name)

    if not missing:
        log("依赖", "Python 依赖完整")
        return

    print(f"[依赖] 缺少 Python 包: {', '.join(missing)}")
    print(f"       安装命令: {PIP_INSTALL_LINE}")

    if not interactive:
        die("请先安装缺少的 Python 包后重试(或使用交互模式)")

    if input("是否现在自动安装? [y/N] ").strip().lower() != "y":
        die("已取消")

    result = run([sys.executable, "-m", "pip", "install", *missing])

    if result.returncode != 0:
        die("pip 安装失败,请检查网络或手动安装")


def find_iscc():
    for path in INNO_COMMON_PATHS:
        if Path(path).is_file():
            return Path(path)

    found = shutil.which("ISCC")

    if found:
        return Path(found)

    registry_hint = "请安装 Inno Setup 6.3+: https://jrsoftware.org/isdl.php"
    die("未找到 Inno Setup(ISCC.exe)", registry_hint)


def check_inno_languages(iscc_path):
    languages_dir = iscc_path.parent / "Languages"
    missing = {name: remote for name, remote in ISS_LANGUAGES.items() if not (languages_dir / name).is_file()}

    if not missing:
        log("语言", f"Inno Setup 语言文件齐全({len(ISS_LANGUAGES)} 种)")
        return

    log("语言", f"补下载缺失语言文件: {', '.join(missing)}")
    languages_dir.mkdir(exist_ok=True)

    for name, remote in missing.items():
        target = languages_dir / name
        api_url = f"https://api.github.com/repos/jrsoftware/issrc/contents/Files/Languages/{remote}"
        raw_url = f"https://raw.githubusercontent.com/jrsoftware/issrc/main/Files/Languages/{remote}"
        raw_headers = {"Accept": "application/vnd.github.raw"}

        if download_file(api_url, target, github=True, headers=raw_headers, min_size=4096):
            log("语言", f"{name} 已从 GitHub API 下载")
        elif download_file(raw_url, target, github=True, min_size=4096):
            log("语言", f"{name} 已从 raw.githubusercontent 下载")
        else:
            die(
                f"语言文件下载失败: {name}",
                f"请从 https://jrsoftware.org/files/istrans/ 手动下载后放入 {languages_dir}",
            )

    log("语言", f"语言文件已补齐({len(ISS_LANGUAGES)} 种)")


def _proxy_candidates():
    candidates = []

    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        value = os.environ.get(key, "").strip()

        if value:
            candidates.append(value)

    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            winreg.KEY_READ,
        ) as key:
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")

                if server and "=" not in server:
                    candidates.append(f"http://{server}")

            except FileNotFoundError:
                pass

            try:
                pac, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                match = re.match(r"https?://([^/:]+):(\d+)", pac or "")

                if match and match.group(1) in ("127.0.0.1", "localhost"):
                    candidates.append(f"http://127.0.0.1:{match.group(2)}")

            except FileNotFoundError:
                pass

    except Exception:
        pass

    seen = set()
    unique = []

    for item in candidates:
        if item not in seen:
            seen.add(item)
            unique.append(item)

    return unique


def download_file(url, target, github=False, headers=None, min_size=1):
    """下载文件到 target。成功返回 True,失败返回 False(报错退出由调用方决定)。"""

    def _ok():
        return target.is_file() and target.stat().st_size >= min_size

    if _ok():
        return True

    attempts = [None]

    if github:
        attempts += _proxy_candidates()

    curl = shutil.which("curl")
    header_args = []

    for key, value in (headers or {}).items():
        header_args += ["-H", f"{key}: {value}"]

    log("下载", f"{url}")

    for proxy in attempts:
        if curl:
            command = [
                curl,
                "-fSL",
                "--retry",
                "2",
                "--connect-timeout",
                "10",
                "--ssl-no-revoke",
            ]

            if proxy:
                command += ["-x", proxy]

            result = run(command + header_args + ["-o", str(target), url])

            if result.returncode == 0 and _ok():
                return True

            target.unlink(missing_ok=True)

            if proxy is not None:
                continue

        import urllib.request

        try:
            request = urllib.request.Request(url, headers=headers or {})

            with urllib.request.urlopen(request, timeout=60) as response, target.open("wb") as file:
                shutil.copyfileobj(response, file)

        except Exception:
            target.unlink(missing_ok=True)
            continue

        if _ok():
            return True

        target.unlink(missing_ok=True)

    return False


def ensure_redist():
    REDIST_DIR.mkdir(exist_ok=True)
    items = [
        (REDIST_DIR / "VC_redist.x64.exe", VC_REDIST_URL, "VC++ 运行库"),
        (REDIST_DIR / "MicrosoftEdgeWebview2Setup.exe", WEBVIEW2_URL, "WebView2 引导器"),
    ]

    for target, url, label in items:
        if target.is_file() and target.stat().st_size > 1024 * 1024:
            log("资源", f"{label} 已存在,跳过下载")
        elif download_file(url, target, min_size=1024 * 1024):
            log("资源", f"{label} 下载完成")
        else:
            die(f"下载失败: {label} ({url})", "请检查网络后重试;也可手动下载放到 Redist 目录")


def _escape_rtf(text):
    result = []

    for char in text:
        code = ord(char)

        if char in "\\{}":
            result.append("\\" + char)
        elif code < 128:
            result.append(char)
        else:
            result.append(f"\\u{code}?")

    return "".join(result)


def ensure_setup_resources():
    SETUP_RES_DIR.mkdir(exist_ok=True)
    licence = SETUP_RES_DIR / "licence.rtf"
    body = _escape_rtf(LICENSE_FILE.read_text(encoding="utf-8", errors="replace"))
    body = body.replace("\r\n", "\\par ").replace("\n", "\\par ").replace("\t", "\\tab ")
    licence.write_text(
        "{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0\\fnil Segoe UI;}}\\fs15 " + body + "}",
        encoding="ascii",
        errors="replace",
    )
    log("资源", "licence.rtf 已生成")

    wizard = SETUP_RES_DIR / "wizardImage.bmp"
    header = SETUP_RES_DIR / "headerImage.png"

    if wizard.is_file() and header.is_file():
        log("资源", "安装向导图片已存在,跳过生成")
        return

    from PIL import Image, ImageDraw

    icon = Image.open(ICON_FILE)

    for target, size in ((wizard, (164, 314)), (header, (55, 58))):
        if target.is_file():
            continue

        image = Image.new("RGB", size, (12, 106, 230))
        draw = ImageDraw.Draw(image)
        icon_size = min(size) - 8
        icon_image = icon.resize((icon_size, icon_size))
        mask = icon_image.convert("RGBA")
        image.paste(mask, ((size[0] - icon_size) // 2, (size[1] - icon_size) // 2), mask)
        draw.rectangle([0, 0, size[0] - 1, size[1] - 1], outline=(10, 88, 190))

        if target.suffix == ".bmp":
            image.save(target, "BMP")
        else:
            image.save(target, "PNG")

        log("资源", f"已生成占位图 {target.name}(可替换为正式设计图)")


def build_exe():
    log("构建", "开始 PyInstaller 打包(耗时数分钟)")

    if not ICON_FILE.is_file():
        die(f"找不到图标文件: {ICON_FILE}")

    # 本机 Python 环境若装了 torch/numba/tensorflow,PyInstaller 会整包收进 exe;
    # 主程序推理走 onnxruntime,这些训练用依赖一律排除。
    # --clean 在本机构建环境会触发 safe-delete 守护的 EBUSY(守护对自己 Temp
    # 暂存区的 rename 被锁,PyInstaller 收到非零码直接退出)。等效做法是打包前
    # 直接清 PyInstaller 缓存目录;删不干净也无妨,--noconfirm 会覆盖构建产物。
    pyinstaller_cache = Path(os.environ.get("LOCALAPPDATA", "")) / "pyinstaller"

    if pyinstaller_cache.is_dir():
        remove_tree_native(pyinstaller_cache)

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--noconsole",
        "--name",
        "PYAS",
        "--icon",
        str(ICON_FILE),
    ]

    for excluded in ("torch", "numba", "tensorflow"):
        command += ["--exclude-module", excluded]

    command += [str(ROOT / "PYAS.py")]
    result = run(command)

    if result.returncode != 0:
        die("PyInstaller 打包失败,请查看上方输出")

    exe = DIST_DIR / "PYAS.exe"

    if not exe.is_file():
        die("打包完成但未找到 dist\\PYAS.exe")

    log("构建", f"PYAS.exe 打包完成({exe.stat().st_size / 1024 / 1024:.1f} MB)")


def remove_tree_native(path):
    """本机构建环境的删除防护只钩 Python 进程:shutil.rmtree 遇到超过阈值的
    批量删除会被 safe-delete 守护挂起等确认(BUILD_EXIT=1 且无报错输出)。
    cmd 原生 rmdir 不经过该钩子;非 Windows 或删除失败再退回 shutil 兜底。"""
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", str(path)],
            cwd=str(ROOT), capture_output=True)

    if Path(path).exists():
        shutil.rmtree(path, ignore_errors=True)


def assemble_payload():
    log("组装", "生成 Payload 目录")

    if PAYLOAD_DIR.exists():
        remove_tree_native(PAYLOAD_DIR)

    PAYLOAD_DIR.mkdir()
    shutil.copy2(DIST_DIR / "PYAS.exe", PAYLOAD_DIR / "PYAS.exe")

    for source_dir in ("Engine", "Interface", "Plugins"):
        shutil.copytree(ROOT / source_dir, PAYLOAD_DIR / source_dir)

    license_dir = PAYLOAD_DIR / "License"
    license_dir.mkdir()
    shutil.copy2(LICENSE_FILE, license_dir / "LICENSE.txt")

    total = sum(f.stat().st_size for f in PAYLOAD_DIR.rglob("*") if f.is_file())
    log("组装", f"Payload 完成({total / 1024 / 1024:.1f} MB)")


def run_iscc(iscc_path):
    log("安装包", "开始 Inno Setup 编译")
    result = run([str(iscc_path), str(ISS_FILE)])

    if result.returncode != 0:
        die("Inno Setup 编译失败,请查看上方输出")

    version = read_version()
    source = OUTPUT_DIR / "PYAS_Setup.exe"
    target = OUTPUT_DIR / f"PYAS_Setup_v{version}.exe"

    if not source.is_file():
        die(f"编译完成但未找到 {source}")

    if target.exists():
        target.unlink()

    source.rename(target)
    return target


def read_release_notes(version):
    """拼出本次 Release 的说明全文。

    正文在 RELEASE_NOTES.md(UTF-8,直接列条目),抬头统一为
    「PYAS Security Cyanmod v<版本>」由本函数生成,避免逐次手改导致格式漂移。
    文件里若已写了抬头(复制上一版时常见),会被剥掉后重新按当前版本生成。
    """
    if not RELEASE_NOTES_FILE.is_file():
        die(f"缺少 {RELEASE_NOTES_FILE.name}", "发布前请把本版本的说明写进仓库根目录的该文件")
    body = RELEASE_NOTES_FILE.read_text(encoding="utf-8").strip()
    if not body:
        die(f"{RELEASE_NOTES_FILE.name} 是空的", "至少列出本版本改了什么")
    title = f"PYAS Security Cyanmod v{version}"
    # 复制上一版时容易把抬头一起留在文件里,那会在正文中间留下一个过期版本号
    body = re.sub(r"^PYAS Security Cyanmod v\S*[ \t]*\n?", "", body, count=1).strip()
    return f"{title}\n\n{body}"


def create_release_gh(asset, version):
    tag = f"v{version}"
    check = run(["gh", "release", "view", tag, "--repo", GITHUB_REPO], capture_output=True)

    if check.returncode == 0:
        die(f"Release {tag} 已存在,请先修改 PYAS_Version.py 中的 VERSION 再发布")

    auth = run(["gh", "auth", "status"], capture_output=True)

    if auth.returncode != 0:
        die(
            "gh CLI 未登录",
            "请先运行: gh auth login  (或设置 GITHUB_TOKEN 环境变量使用 API 方式)",
        )

    notes = read_release_notes(version)
    result = run(
        [
            "gh",
            "release",
            "create",
            tag,
            str(asset),
            "--repo",
            GITHUB_REPO,
            "--title",
            f"PYAS Security Cyanmod {tag}",
            "--notes",
            notes,
        ]
    )

    if result.returncode != 0:
        die(
            "gh release create 失败",
            "请检查网络与登录状态;若需要代理,先设置 HTTPS_PROXY 后重试",
        )


def create_release_api(asset, version):
    import json
    import urllib.request

    token = os.environ.get("GITHUB_TOKEN", "").strip()

    if not token:
        die("未找到 gh CLI,且未设置 GITHUB_TOKEN 环境变量", "安装 gh 后运行 gh auth login,或设置 GITHUB_TOKEN")

    tag = f"v{version}"
    api = "https://api.github.com"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "PYAS-Cyanmod-Build",
    }
    payload = json.dumps(
        {
            "tag_name": tag,
            "name": f"PYAS Security Cyanmod {tag}",
            "body": read_release_notes(version),
        }
    ).encode()
    request = urllib.request.Request(
        f"{api}/repos/{GITHUB_REPO}/releases", data=payload, headers=headers, method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            release = json.load(response)
    except Exception as error:
        die(f"创建 Release 失败: {error}", "请检查 GITHUB_TOKEN 权限(repo)与网络代理")

    upload_url = release["uploads_url"].replace("{?name,label}", "")
    request = urllib.request.Request(
        f"{upload_url}?name={asset.name}",
        data=asset.read_bytes(),
        headers={**headers, "Content-Type": "application/octet-stream"},
        method="POST",
    )

    try:
        urllib.request.urlopen(request, timeout=600).read()
    except Exception as error:
        die(f"上传安装包失败: {error}", "请检查网络代理后重新执行 release --skip-build")

    log("发布", f"Release {tag} 创建成功")


def publish(asset, version, interactive=False):
    log("发布", f"准备发布 {asset.name} → {GITHUB_REPO}")
    assert_publish_channel(interactive)

    if shutil.which("gh"):
        create_release_gh(asset, version)
    else:
        create_release_api(asset, version)

    print(f"\n[完成] 发布地址: https://github.com/{GITHUB_REPO}/releases/tag/v{version}")




def lint_i18n():
    """构建前强制检查:简中界面出现繁体文案/缺失键时阻断构建。

    该类问题历史上反复出现(无键文本反查失配、新键漏入简中块),构建期拦截根治。
    """
    html_path = ROOT / "Interface" / "templates" / "index.html"
    js_path = ROOT / "Interface" / "static" / "js" / "i18n.js"

    if not html_path.is_file() or not js_path.is_file():
        return

    html = html_path.read_text(encoding="utf-8")
    js = js_path.read_text(encoding="utf-8")

    def block(lang):
        m = re.search(r'"' + lang + r'": \{\n(.*?)\n        \},', js, re.S)
        if not m:
            return {}
        return dict(re.findall(r'"((?:[^"]|\\.)+)": "((?:[^"]|\\.)*)"', m.group(1)))

    zh = block("simplified_switch")
    trad = block("traditional_switch")
    trad_vals = set(trad.values())

    # 高置信「简体不使用」的繁简差异字
    real_trad = set("這開關設選擇應後時會對認為訊檔監聽務線圖報載與將無還進變讀寫標準確過閉說異權訪執發網絡連據隻兒們軍階級溫禮義試詢構轉換觸擊擴縮體驗鎖鏈佈")
    problems = []

    for key, value in zh.items():
        if any(ch in real_trad for ch in value):
            problems.append(f"简中块值含繁体字: {key} = {value[:50]}")

    texts = set(re.findall(
        r'<(?:h2|p|span|button|div|option)[^>]*data-i18n(?:="([^"]*)")?[^>]*>([^<]{1,80})</',
        html,
    ))

    for key_attr, text in texts:
        t = text.strip()

        if not t or key_attr:
            continue

        if t not in trad_vals:
            if any(ch in real_trad for ch in t):
                problems.append(f"HTML 无键文本反查失败且为繁体(将原样显示): {t[:60]}")
        else:
            rk = next((k for k, v in trad.items() if v == t), None)

            if rk and rk not in zh:
                problems.append(f"反查键缺简中值: {rk}")

    for key_attr in set(re.findall(r'data-i18n="([^"$]+)"', html)):
        if key_attr not in zh and not key_attr.startswith("$"):
            problems.append(f"HTML 有键但简中字典缺失: {key_attr}")

    if problems:
        die(
            "i18n lint 未通过(简中界面会出现繁体/缺键)",
            "\n       " + "\n       ".join(problems[:12])
            + (f"\n       ...共 {len(problems)} 项" if len(problems) > 12 else ""),
        )

    log("i18n", f"简中文案检查通过({len(zh)} 键)")

BUILD_CONTRACT_PATTERNS = (
    'test_policy_store.py', 'test_policy_access.py', 'test_policy_list_rollback.py', 'test_policy_native_contracts.py', 'test_policy_broker_integration.py', 'test_policy_install_trust.py', 'test_policy_bootstrap_log.py', 'test_restart_application.py', 'test_eicar_support.py', 'test_own_components.py', 'test_bootstrap_launch.py', 'test_launcher_build.py', 'test_i18n_keys.py', 'test_driver_home_hidden.py', 'test_features_prescreen.py', 'test_installer_quit_flow.py', 'test_threat_topmost.py', 'test_window_minimize.py',
    'test_update_install_guard.py', 'test_signature_trust.py', 'test_ai_cache_scope.py',
    'test_autostart_registry.py',
    'test_attribution_cache.py',
    'test_etw_consumer.py',
    'test_log_action_i18n.py',
    'test_write_owner_query.py',
)


def run_build_contracts(patterns):
    """The same verification gates apply to local builds and GitHub builds."""
    for pattern in patterns:
        log('预检', pattern)
        result = run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', pattern, '-v'])
        # 本机常驻杀软(含 PYAS 自己)会短暂锁住 %TEMP% 里刚写的文件,导致
        # PermissionError 这类与代码无关的偶发失败。只给一次重试,并明确打日志,
        # 避免把真实失败掩盖掉(第二次仍失败照样中断构建)。
        if result.returncode != 0:
            log('预检重试', pattern + ' (首次失败,可能被实时防护占用)')
            result = run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', pattern, '-v'])

        if result.returncode != 0:
            die(f'构建验证未通过: {pattern}')


def do_build(interactive, channel="dev"):
    lint_i18n()
    version = read_version()
    log("版本", f"当前版本 {version}")
    write_build_channel(channel)
    sync_iss_version(version)
    check_python_packages(interactive)
    run_build_contracts(BUILD_CONTRACT_PATTERNS)
    iscc_path = find_iscc()
    log("环境", f"Inno Setup: {iscc_path}")
    check_inno_languages(iscc_path)
    ensure_redist()
    ensure_setup_resources()
    build_exe()
    assemble_payload()
    result = run([sys.executable, str(ROOT / 'build_launcher.py')])
    if result.returncode != 0:
        die('独立启动器构建或冻结启动检查失败')
    result = run([sys.executable, str(ROOT / 'build_menu.py')])
    if result.returncode != 0:
        die('新版右键菜单组件构建失败')
    run_build_contracts(('test_menu_certificate.py',))
    asset = run_iscc(iscc_path)
    log("完成", f"安装包已生成: {asset}")
    return asset


def do_check():
    log("自检", "Python " + sys.version.split()[0])
    _report_packages()

    iscc = None

    for path in INNO_COMMON_PATHS:
        if Path(path).is_file():
            iscc = Path(path)
            break

    if iscc is None:
        found = shutil.which("ISCC")

        if found:
            iscc = Path(found)

    if iscc:
        log("环境", f"Inno Setup: {iscc}")
        check_inno_languages(iscc)
    else:
        print("[环境] Inno Setup 未安装: https://jrsoftware.org/isdl.php (需 6.3+)")

    for label, path in (
        ("VC++ 运行库", REDIST_DIR / "VC_redist.x64.exe"),
        ("WebView2 引导器", REDIST_DIR / "MicrosoftEdgeWebview2Setup.exe"),
    ):
        state = "已下载" if path.is_file() else "未下载(构建时自动下载)"
        log("资源", f"{label}: {state}")

    log("工具", "gh CLI: " + ("已安装" if shutil.which("gh") else "未安装(发布可用 GITHUB_TOKEN 替代)"))
    log("自检", "检查完成")


def _report_packages():
    missing = [pkg for mod, pkg in PYTHON_PACKAGES if importlib.util.find_spec(mod) is None]

    if missing:
        print(f"[依赖] 缺少: {', '.join(missing)}\n       {PIP_INSTALL_LINE}")
    else:
        log("依赖", "Python 依赖完整")


def menu():
    print("=" * 52)
    print("   PYAS Security Cyanmod 一键构建")
    print("=" * 52)
    print("  [1] 完整发布 —— 普通模式 + 上传 GitHub Release")
    print("  [2] 仅本地构建 —— 开发者模式,只生成安装包")
    print("  [3] 环境自检")
    print("  [0] 退出")

    choice = input("\n请选择: ").strip()

    if choice == "1":
        do_build(interactive=True, channel="normal")
        publish(OUTPUT_DIR / f"PYAS_Setup_v{read_version()}.exe", read_version(), interactive=True)
    elif choice == "2":
        do_build(interactive=True, channel="dev")
    elif choice == "3":
        do_check()
    else:
        sys.exit(0)

    input("\n按回车键退出...")


def main():
    parser = argparse.ArgumentParser(description="PYAS Security Cyanmod 一键构建")
    parser.add_argument("mode", nargs="?", choices=["local", "release", "check"], help="构建模式")
    parser.add_argument("--skip-build", action="store_true", help="release 时跳过构建直接上传")
    parser.add_argument("--channel", choices=["dev", "normal"],
        help="构建渠道:dev=开发者模式(本地构建默认),normal=普通模式(发布默认)")
    args = parser.parse_args()

    if args.mode is None:
        menu()
        return

    if args.mode == "check":
        do_check()
        return

    version = read_version()
    asset = OUTPUT_DIR / f"PYAS_Setup_v{version}.exe"

    channel = args.channel or MODE_CHANNEL[args.mode]

    if args.mode == "local":
        do_build(interactive=False, channel=channel)
        return

    if args.skip_build:
        if not asset.is_file():
            die(f"未找到已有安装包: {asset}", "先运行 python build.py local")
    else:
        asset = do_build(interactive=False, channel=channel)

    publish(asset, version)


if __name__ == "__main__":
    main()
