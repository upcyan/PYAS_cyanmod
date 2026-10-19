# -*- coding: utf-8 -*-
"""PYAS Security Cyanmod 用户自测脚本(黑盒,仅用标准库)。

两种模式:
    py -3 selftest.py             自助测试:列出项目菜单,自选编号执行,可反复测
    py -3 selftest.py --auto      自动测试:全量跑一遍(智能体项含后台扫描等待)
    py -3 selftest.py --fast      自动测试的快速版(智能体项只布置环境不等待)
    py -3 selftest.py --only X    只跑名字含 X 的项(脚本化用)

适用:源码目录(py -3 直接跑)或已安装机器(把本脚本和 selftest.bat 放任意目录)。
本脚本只读系统状态、只创建/清理自己的测试文件,不修改 PYAS 配置。「智能体加固」
提供端到端自动测试(启动仿真名进程,验证后台监控真的在记录);「交互弹窗(端到端)」
往数据目录写一个测试请求哨兵,由运行中的应用弹出标题带 [Self Test] 的真实裁决窗,
用户点允许/阻止后脚本轮询日志验证整条链路(决策只记日志,不触发任何引擎动作)。
"""
import ctypes
import ctypes.wintypes
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

IS_NT = os.name == "nt"
PROGRAM_DATA = os.environ.get("ALLUSERSPROFILE", "C:\\ProgramData")
CONFIG_PATH = os.path.join(PROGRAM_DATA, "PYAS.Policy", "Config.json")
LOCAL_DATA = os.environ.get("LOCALAPPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Local"))
USER_DATA = os.path.join(LOCAL_DATA, "PYAS")
REPORT_PATH = os.path.join(USER_DATA, "Report.json")
SELFTEST_EXE = os.path.join(os.environ.get("TEMP", "."), "claude-selftest.exe")
AGENT_WAIT_SECONDS = 400  # 后台监控 5 分钟一轮,留 6.5 分钟余量

FAST = "--fast" in sys.argv
AUTO = "--auto" in sys.argv
ONLY = ""
if "--only" in sys.argv:
    ONLY = sys.argv[sys.argv.index("--only") + 1]

# 智能体项是否等待后台扫描:--auto 默认等(--fast 时不等);自助模式运行时逐次询问
WAIT_FOR_AGENT = AUTO and not FAST

RESULTS = []
CHECKS = []

# 「交互弹窗(端到端)」的测试请求哨兵:应用侧(DialogMixin.selftest_threat_watchdog)
# 检测到就弹一个标题带 [Self Test] 的真实裁决窗,决策只记日志不触发引擎动作
SELFTEST_SENTINEL = os.path.join(USER_DATA, "selftest_threat.json")
DIALOG_WAIT_SECONDS = 180  # 用户留看点弹窗的时间


def out(text):
    print(text, flush=True)


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f), None
    except FileNotFoundError:
        return {}, "配置文件不存在(未安装或未首次运行?)"
    except Exception as exc:
        return {}, f"配置文件解析失败: {exc}"


def load_report():
    """返回 (条目列表, 错误)。文件是 JSON 数组,由 PYAS 周期性整体重写。"""
    try:
        with open(REPORT_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return (data if isinstance(data, list) else []), None
    except FileNotFoundError:
        return [], "Report.json 不存在(程序未运行或刚安装?)"
    except Exception as exc:
        return [], f"Report.json 解析失败: {exc}"


def report_mtime():
    try:
        return time.time() - os.path.getmtime(REPORT_PATH)
    except OSError:
        return None


def pyas_running():
    try:
        raw = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq PYAS.exe", "/FO", "CSV", "/NH"],
            encoding="gbk", errors="replace", stderr=subprocess.DEVNULL)
        return "PYAS.exe" in raw
    except Exception:
        return False


def driver_state():
    """返回 PYAS_Driver 服务状态字符串:RUNNING/STOPPED/MISSING/UNKNOWN。"""
    try:
        raw = subprocess.check_output(
            ["sc", "query", "PYAS_Driver"], encoding="gbk", errors="replace",
            stderr=subprocess.DEVNULL)
    except Exception:
        return "UNKNOWN"

    for line in raw.splitlines():
        line = line.strip()

        if line.startswith("STATE"):
            if "RUNNING" in line:
                return "RUNNING"

            if "STOPPED" in line:
                return "STOPPED"

    return "MISSING" if "1060" in raw else "UNKNOWN"


def notification_enabled():
    """与 PYAS_System.check_notification_permission 同源的注册表检查(全局层)。"""
    import winreg

    try:
        with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\PushNotifications",
                0, winreg.KEY_READ) as key:
            if int(winreg.QueryValueEx(key, "ToastEnabled")[0]) == 0:
                return False
    except FileNotFoundError:
        pass
    except Exception:
        return True

    try:
        with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
                0, winreg.KEY_READ) as key:
            if int(winreg.QueryValueEx(key, "NOC_GLOBAL_SETTING_TOASTS_ENABLED")[0]) == 0:
                return False
    except FileNotFoundError:
        pass
    except Exception:
        pass

    return True


def check(name, hint=""):
    """登记一个测试项;hint 显示在菜单里(耗时/前提提示)。"""
    def register(func):
        CHECKS.append({"name": name, "hint": hint, "func": func})
        return func
    return register


@check("运行状态")
def check_running(cfg, cfg_err):
    if cfg_err:
        return "FAIL", cfg_err

    if pyas_running():
        return "PASS", "PYAS.exe 正在运行"

    return "FAIL", "PYAS.exe 未在运行——从开始菜单或托盘启动后重跑"


@check("配置与开关")
def check_config(cfg, cfg_err):
    if cfg_err:
        return "FAIL", cfg_err

    flags = {
        "文件防护(document_switch)": cfg.get("document_switch"),
        "交互模式(interactive_switch)": cfg.get("interactive_switch"),
        "云端检测(cloud_switch)": cfg.get("cloud_switch"),
        "智能体加固(agent_switch)": cfg.get("agent_switch"),
        "通知渠道(notify_channel)": cfg.get("notify_channel"),
    }
    detail = ";".join(f"{k}={v}" for k, v in flags.items())
    on = [k for k, v in flags.items() if v is True]

    if not any(v is True for v in flags.values() if isinstance(v, bool)):
        return "WARN", f"防护开关全部未开启({detail})——先到设置页开启再测"
    return "PASS", detail


@check("日志活性")
def check_report(cfg, cfg_err):
    entries, err = load_report()

    if err:
        return "FAIL", err

    age = report_mtime()

    if age is None:
        return "FAIL", "Report.json 不存在"

    if age > 900:
        return "WARN", f"Report.json 已 {int(age/60)} 分钟没写入(程序可能在无人活动状态,不一定是故障)"

    return "PASS", f"共 {len(entries)} 条记录,最近 {int(age)} 秒前有写入"


@check("通知权限")
def check_notify(cfg, cfg_err):
    if not IS_NT:
        return "SKIP", "非 Windows"

    enabled = notification_enabled()

    if enabled:
        return "PASS", "系统通知已开启(应用层开关如有单独关闭,去 设置→通知 里找 PYAS)"

    return "WARN", "Windows 通知被关闭:设置→系统→通知 打开,否则拦截提醒收不到"


@check("驱动防护")
def check_driver(cfg, cfg_err):
    if cfg_err:
        return "SKIP", cfg_err

    state = driver_state()

    if cfg.get("driver_switch"):
        if state == "RUNNING":
            return "PASS", "PYAS_Driver 服务运行中"
        if state == "STOPPED":
            return "WARN", "驱动开关已开但服务停止——常见原因是签名策略拦截,见关于页说明"
        return "WARN", f"服务状态异常: {state}"

    if state == "RUNNING":
        return "INFO", "驱动服务在运行,但驱动防护开关未开启"

    return "SKIP", "驱动防护未开启(驱动防护为全自动层,开启后无需交互)"


@check("更新通道")
def check_update(cfg, cfg_err):
    version = (cfg.get("version") or "?") if not cfg_err else "?"

    try:
        request = urllib.request.Request(
            "https://api.github.com/repos/87owo/PYAS/releases?per_page=1",
            headers={"User-Agent": "PYAS-selftest"})
        with urllib.request.urlopen(request, timeout=8) as response:
            data = json.load(response)
        latest = (data or [{}])[0].get("tag_name", "?")
        note = f"本机版本 {version};上游最新 {latest};网络可达"

        if version != "?" and str(latest).lstrip("v").startswith(f"{version.split('-')[0]}"):
            return "PASS", note

        return "INFO", note + "(版本对比仅供参考,以程序内「检查更新」为准)"
    except Exception as exc:
        return "WARN", f"GitHub 暂时连不上({exc})——不影响防护,只影响检查更新"


@check("智能体加固(端到端)", "约 5-7 分钟(等后台扫描);关闭等待则只布置环境")
def check_agent(cfg, cfg_err):
    if cfg_err:
        return "SKIP", cfg_err

    if not cfg.get("agent_switch", True):
        return "FAIL", "agent_switch 已关闭——到 AI+ 页把「智能体加固」打开后重跑"

    src = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "notepad.exe")

    if not os.path.isfile(src):
        return "SKIP", "找不到 notepad.exe,无法布置仿真进程"

    try:
        shutil.copyfile(src, SELFTEST_EXE)
    except Exception as exc:
        return "SKIP", f"无法创建测试进程文件: {exc}"

    proc = None

    try:
        proc = subprocess.Popen([SELFTEST_EXE], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        out(f"    仿真进程已启动: {SELFTEST_EXE}(pid {proc.pid})")

        if not WAIT_FOR_AGENT:
            return "INFO", ("未等待:开 AI+ 页(会立即扫一次)看「检测到智能体」里有没有"
                            " claude-selftest.exe;然后重跑本项并选择等待,验证自动判定")

        out("    等待后台扫描(每 5 分钟一轮,最长等 6.5 分钟,可 Ctrl+C 中止)…")

        deadline = time.time() + AGENT_WAIT_SECONDS

        while time.time() < deadline:
            time.sleep(5)
            entries, err = load_report()

            if err:
                continue

            for entry in entries:
                action = str(entry.get("action", ""))
                source = str(entry.get("source", ""))

                if action == "Agent Detected" and "claude-selftest" in source.lower():
                    return "PASS", (f"后台监控已捕获仿真智能体(source={source},"
                                    f"detail={entry.get('detail', '')})")

        return "FAIL", ("等待超时没看到检测记录——确认 agent_switch 已开,"
                        "或进一次 AI+ 页触发即时扫描后重跑")
    finally:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass

        try:
            os.remove(SELFTEST_EXE)
        except OSError:
            pass


@check("实时文件防护(指引)")
def check_realtime(cfg, cfg_err):
    if cfg_err:
        return "SKIP", cfg_err

    if not cfg.get("document_switch"):
        return "SKIP", "文件防护未开启(设置→防护→文件防护)。开启后监控用户目录的文件改动"

    return "INFO", ("已开启。可用标准 EICAR 测试串自测:在用户目录新建一个 .txt,"
                    "写入 EICAR 公布的测试标记并保存,实时防护应拦截并记入隔离区;"
                    "该标记无害,验证完删除即可。其他样本仍需你信任来源")


@check("交互弹窗(端到端)", hint="需应用运行中+交互模式开启;会弹一个真实的测试裁决窗")
def check_interactive(cfg, cfg_err):
    if cfg_err:
        return "SKIP", cfg_err

    if not pyas_running():
        return "SKIP", "PYAS 未运行——先启动应用再跑本项"

    if not cfg.get("interactive_switch"):
        return "SKIP", "交互模式未开启(设置→防护→交互模式)"

    if cfg.get("dnd_switch"):
        out("    提示:免打扰模式开着,弹窗可能被静默排队,处理完同样会记录")

    nonce = os.urandom(8).hex()
    payload = {
        "nonce": nonce,
        "title": "交互弹窗端到端自测",
        "message": ("这是 selftest 发起的测试告警,不是真实拦截。\r\n"
                    "点「允许」或「阻止」任意一个即可完成测试"
                    "(「永久允许」「误报」对本测试无效)。"),
    }
    os.makedirs(os.path.dirname(SELFTEST_SENTINEL), exist_ok=True)

    try:
        with open(SELFTEST_SENTINEL, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
    except OSError as exc:
        return "SKIP", f"写不进数据目录({exc})——检查 {os.path.dirname(SELFTEST_SENTINEL)} 权限"

    out("    测试裁决窗应已弹出(标题带 [Self Test]),点「允许」或「阻止」任意一个…")

    deadline = time.time() + DIALOG_WAIT_SECONDS

    while time.time() < deadline:
        time.sleep(2)
        entries, err = load_report()

        if err:
            continue

        for entry in reversed(entries):
            detail = str(entry.get("detail", ""))

            if entry.get("action") == "Selftest Dialog" and nonce in detail:
                choice = "允许" if "decision=allow" in detail else "阻止"
                return "PASS", (f"弹窗弹出且裁决已落盘:你点了{choice}"
                                "(桥接→弹窗→裁决→日志整条链路都通)")

    # 超时清掉哨兵,避免升级新版后残留的请求突然弹出来
    try:
        os.remove(SELFTEST_SENTINEL)
    except OSError:
        pass

    return "FAIL", ("180 秒内没等到裁决记录——弹窗没弹出(应用可能是旧版本,"
                    "重装新包后重跑)或一直没有点")


def run_checks(selection):
    """执行选中的测试项,返回本批失败数。selection 为 CHECKS 下标列表。"""
    cfg, cfg_err = load_config()

    if not cfg_err:
        out(f"版本: {cfg.get('version', '?')}    配置: {CONFIG_PATH}")

    failures = 0

    for index in selection:
        item = CHECKS[index]
        name, func = item["name"], item["func"]

        try:
            status, note = func(cfg, cfg_err)
        except Exception as exc:
            status, note = "FAIL", f"检查项异常: {exc}"

        if status == "FAIL":
            failures += 1

        out(f"[{status:^4}] {name}  {note}")
        RESULTS.append(f"[{status}] {name}  {note}")

    out("-" * 64)
    out(f"本批结果: {len(selection)} 项,失败 {failures}")
    return failures


def save_results(verdict):
    try:
        report_file = os.path.join(os.environ.get("TEMP", "."), "PYAS_selftest_report.txt")
        with open(report_file, "a", encoding="utf-8") as f:
            f.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + verdict + "\n")
            f.write("\n".join(RESULTS[-32:]) + "\n")
        out(f"记录已追加: {report_file}")
    except OSError:
        pass


def parse_selection(raw):
    """解析用户输入:'1,3' / '1 3' / '1，3'(中文逗号) / 空=全部;非法编号忽略。"""
    raw = raw.strip().replace("，", ",").replace("、", ",")

    if not raw or raw.lower() in ("a", "all", "all"):
        return list(range(len(CHECKS)))

    picked = []

    for token in raw.replace(",", " ").split():
        if token.isdigit():
            index = int(token) - 1

            if 0 <= index < len(CHECKS) and index not in picked:
                picked.append(index)

    return picked


def menu():
    """自助测试:菜单循环,自选项目反复执行。"""
    while True:
        out("")
        out("=" * 64)
        out("自助测试——输入编号执行(可多选,空格/逗号分隔);回车=全部;a=全部;q=退出")
        out("-" * 64)

        for index, item in enumerate(CHECKS, 1):
            hint = f"    —— {item['hint']}" if item["hint"] else ""
            out(f"  {index}. {item['name']}{hint}")

        try:
            raw = input("选择> ")
        except (EOFError, KeyboardInterrupt):
            out("")
            return 0

        if raw.strip().lower() in ("q", "quit", "exit", "退出"):
            return 0

        selection = parse_selection(raw)

        if not selection:
            out("没有有效编号,请重新输入。")
            continue

        global WAIT_FOR_AGENT

        if any(CHECKS[i]["name"].startswith("智能体加固") for i in selection) and not AUTO and not FAST:
            answer = input("智能体项是否等待后台扫描(最长 6.5 分钟,更严谨)? [y/N] ").strip().lower()
            WAIT_FOR_AGENT = answer in ("y", "yes", "是")

        out("=" * 64)
        failures = run_checks(selection)
        save_results(f"自助测试 {len(selection)} 项,失败 {failures}")


def auto():
    """自动测试:全量执行(--only 时跑名字匹配的项)。"""
    global WAIT_FOR_AGENT
    WAIT_FOR_AGENT = not FAST

    selection = [i for i, item in enumerate(CHECKS) if not ONLY or ONLY in item["name"]]

    if not selection:
        out(f"没有匹配「{ONLY}」的测试项。")
        return 1

    out("=" * 64)
    out("自动测试——执行 "
        + ", ".join(CHECKS[i]["name"] for i in selection)
        + ("(快速模式:智能体项不等待)" if FAST else ""))
    out("=" * 64)
    failures = run_checks(selection)
    verdict = "存在失败项,建议按提示处理后重跑" if failures else "全部关键项通过"
    out("=" * 64)
    out(f"结论: {verdict}({len(selection)} 项,失败 {failures})")
    save_results(f"自动测试 {len(selection)} 项,失败 {failures}:{verdict}")
    return 1 if failures else 0


def main():
    if not IS_NT:
        out("本脚本仅支持 Windows。")
        return 1

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if ONLY:
        return auto()  # --only 走自动流程,只是范围收窄

    if AUTO:
        return auto()

    return menu()


if __name__ == "__main__":
    sys.exit(main())
