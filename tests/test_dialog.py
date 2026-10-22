# -*- coding: utf-8 -*-
"""PYAS Security Cyanmod 拦截弹窗测试程序。

默认驱动与正式拦截完全相同的 **WebView 弹窗**路径(_WebThreatDialogSession,
720×680 那个带检测证据/AI 建议的窗口):脚本自起一个本地静态服务器 + 隐藏的
pywebview 主窗口,让会话工厂像生产环境一样选中 WebView 会话。
加 --native 可改测原生 Win32 回退弹窗(无主窗口时的降级路径)。

验证内容:
  - 弹窗显示 / 威胁说明 / 倒计时 / 按钮
  - 超时未选择自动拦截
  - 多个威胁的串行排队

用法:
    python test_dialog.py            # 交互菜单
    python test_dialog.py 1          # 单次弹窗(自己点按钮)
    python test_dialog.py 2 [秒]     # 超时自动拦截测试(默认 8 秒)
    python test_dialog.py 3 [秒]     # 连续威胁排队测试(默认 4 秒 x2)
    python test_dialog.py --native 2 # 原生回退弹窗

说明:默认不自动处理;关闭仅收起。计时测试显式启用超时拦截。
真实防护链路的拦截仍由 PYAS 主程序的交互模式开关控制,本工具只测弹窗环节。
"""
import functools
import http.server
import sys
import threading
import time
from pathlib import Path

# 本脚本在 tests/ 子目录里直接运行:把仓库根加进模块搜索路径才能导入 PYAS_* 模块
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PYAS_Config import ConfigMixin
from PYAS_Dialog import DialogMixin, loc_threat_description
import PYAS as pyas_app

NATIVE = "--native" in sys.argv
INTERFACE_DIR = Path(__file__).resolve().parent.parent / "Interface"
APP_WINDOW = None  # webview 模式下注入 FakeApp._window;无主窗口=原生回退

TEST_NOTICE = "【测试弹窗】此窗口仅用于功能测试,无需任何操作,倒计时结束后会自动关闭。"

SAMPLES = [
    ("Process Block", {"source": r"C:\Users\demo\Downloads\trojan_demo.exe", "pid": 4321}),
    ("File Block", {"source": r"C:\Users\demo\Documents\invoice.pdf.exe"}),
    (
        "Network Block",
        {
            "source": r"C:\Users\demo\AppData\Roaming\coinminer_demo.exe",
            "target": "185.222.111.33:443",
            "pid": 7777,
        },
    ),
    (
        "Process DLL Block",
        {"source": r"C:\Users\demo\AppData\Local\Temp\inject_demo.dll", "pid": 1024},
    ),
]

ACTIONS = {
    "Process Block": "进程拦截",
    "File Block": "文件拦截",
    "Network Block": "网络拦截",
    "Process DLL Block": "进程 DLL 拦截",
}


class FakeApp(DialogMixin):
    """只提供 DialogMixin 所需的最小环境;标题与本地化直接借用主程序真实实现。

    _window 由 main() 注入:有窗口=生产 WebView 弹窗;无窗口=原生 Win32 回退弹窗。
    """

    get_block_action_title = pyas_app._MainMixin.get_block_action_title
    _loc = ConfigMixin._loc

    def _ai_endpoint_config(self):
        # 正式实现来自 AIMixin;测试无 AI 配置,返回空三元组即可
        return "", "", ""

    def __init__(self, interactive=True, timeout=30, lang="simplified_switch"):
        self.lock_config = threading.RLock()
        self.lock_interactive = threading.RLock()
        self.pyas_config = {
            "interactive_switch": interactive,
            "interactive_timeout": timeout,
            "language": lang,
        }
        self._window = APP_WINDOW


_shared_app = None


def get_app(timeout=30):
    global _shared_app

    if _shared_app is None:
        _shared_app = FakeApp(timeout=timeout)

    return _shared_app


def start_asset_server():
    """起一个只服务 Interface/ 目录的本地静态服务器,返回主页 URL。

    生产环境的主窗口指向程序内建服务器;threat.html 及其静态资源都按
    /templates/... /static/... 解析,这里用同一套路径约定。
    """
    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(INTERFACE_DIR))
    handler.log_message = lambda *args, **kwargs: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}/templates/index.html"


def prompt_test(action, fields, timeout, app=None):
    """弹出带测试说明的真实拦截弹窗,返回决策(True=拦截)。"""
    app = app or get_app(timeout or 30)
    lines = [TEST_NOTICE, loc_threat_description("simplified_switch", action)]

    if fields.get("source"):
        lines.append(f"来源: {fields['source']}")

    if fields.get("target"):
        lines.append(f"目标: {fields['target']}")

    if fields.get("pid"):
        lines.append(f"进程: {fields['pid']}")

    title = app.get_block_action_title(action)
    return app.show_threat_prompt(title, "\r\n".join(lines), timeout)


def describe(decision, elapsed):
    return f"返回决策: {'拦截' if decision else '放行'}  耗时 {elapsed:.1f} 秒"


def run_single():
    print("\n可用威胁类型:")
    for index, (action, fields) in enumerate(SAMPLES, 1):
        print(f"  [{index}] {ACTIONS[action]}  {fields.get('source', '')}")

    choice = input("选择类型(回车=1): ").strip()

    try:
        index = int(choice) - 1 if choice else 0
        action, fields = SAMPLES[index]
    except (ValueError, IndexError):
        print("输入无效")
        return

    print(f"\n>>> 弹出「{ACTIONS[action]}」测试弹窗(首行已标注为测试,可自行点击按钮)...")
    start = time.monotonic()
    decision = prompt_test(action, fields, None)
    print(describe(decision, time.monotonic() - start))


def run_timeout(timeout=None):
    if timeout is None:
        raw = input("超时秒数(回车=8): ").strip()
        timeout = int(raw) if raw.isdigit() and int(raw) > 0 else 8

    action, fields = SAMPLES[0]
    print(f"\n>>> 弹出测试弹窗,不做任何操作,{timeout} 秒后应自动拦截 ...")
    start = time.monotonic()
    decision = prompt_test(action, fields, timeout)
    elapsed = time.monotonic() - start

    print(describe(decision, elapsed))

    ok = decision and abs(elapsed - timeout) < 3
    print("结果: " + ("PASS(超时自动拦截生效)" if ok else "FAIL(行为不符合预期)"))


def run_queue(timeout=None):
    if timeout is None:
        raw = input("每个弹窗超时秒数(回车=4): ").strip()
        timeout = int(raw) if raw.isdigit() and int(raw) > 0 else 4

    print(f"\n>>> 同时模拟 2 个威胁,弹窗应逐个串行出现,每个 {timeout} 秒超时 ...")
    results = {}
    app = get_app(timeout)
    start = time.monotonic()

    def worker(index, action, fields):
        began = time.monotonic()
        results[index] = (prompt_test(action, fields, timeout, app), time.monotonic() - began)

    threads = [
        threading.Thread(target=worker, args=(index, *SAMPLES[index]), daemon=True)
        for index in (0, 2)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    total = time.monotonic() - start

    for index, (decision, elapsed) in sorted(results.items()):
        name = ACTIONS[SAMPLES[index][0]]
        print(f"  {name}: {describe(decision, elapsed)}")

    serialized = all(decision for decision, _ in results.values()) and timeout * 2 <= total < timeout * 2 + 5
    print(f"总耗时 {total:.1f} 秒(串行应约 {timeout * 2} 秒)")
    print("结果: " + ("PASS(排队串行生效)" if serialized else "FAIL"))


def menu():
    print("=" * 52)
    print(f"   PYAS Security Cyanmod 拦截弹窗测试"
          f"({'原生回退' if NATIVE else 'WebView 生产弹窗'})")
    print("=" * 52)
    print("  [1] 单次弹窗(自行点击 攔截/放行)")
    print("  [2] 超时自动拦截测试")
    print("  [3] 连续威胁排队测试")
    print("  [0] 退出")
    choice = input("\n请选择: ").strip()

    if choice == "1":
        run_single()
    elif choice == "2":
        run_timeout()
    elif choice == "3":
        run_queue()
    else:
        return

    input("\n按回车键退出...")


def run_flow(mode, timeout):
    if mode == "1":
        run_single()
    elif mode == "2":
        run_timeout(timeout)
    else:
        run_queue(timeout)


def main():
    argv = [arg for arg in sys.argv[1:] if arg != "--native"]
    mode = argv[0] if argv and argv[0] in ("1", "2", "3") else None
    timeout = None

    if len(argv) > 1 and argv[1].isdigit():
        timeout = int(argv[1])

    if NATIVE:
        # 原生回退弹窗:无主窗口,不需要 webview 环境
        run_flow(mode, timeout) if mode else menu()
        return

    import webview

    global APP_WINDOW
    base_url = start_asset_server()
    APP_WINDOW = webview.create_window(
        "PYAS selftest (hidden)", base_url, hidden=True, width=320, height=200)

    def boot():
        # 等隐藏主窗口完成导航:会话要靠它的 URL 解析 threat.html 地址
        for _ in range(50):
            if APP_WINDOW.get_current_url():
                break

            time.sleep(0.2)

        try:
            run_flow(mode, timeout) if mode else menu()
        finally:
            for window in list(webview.windows):
                try:
                    window.destroy()
                except Exception:
                    pass

    webview.start(boot)


if __name__ == "__main__":
    main()
