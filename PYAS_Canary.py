# -*- coding: utf-8 -*-
"""蜜罐文档:用户文档区的诱饵文件,被触碰即高置信勒索告警。

设计约束(2026-10-30 用户定稿):
- **只补强不侵入**:本模块通过宿主已有事件回调的一行 try 调用接入,
  任何异常都在本模块内部消化,绝不影响扫描/拦截/溯源主链路;
- **隐藏与声明**:诱饵带隐藏+系统属性,文件内容内嵌 PYAS 声明,防止
  用户误认为真实文档;被删除后由补种机制自动恢复;
- **误报趋近于零**:正常软件没有任何理由改写这些文件,命中即近乎
  确定是勒索式批量改写(对照:启发计数需要 40 文件/10 秒)。

依赖宿主提供:lock_config/pyas_config/write_log/_loc/path_user,
以及可选的 _behavior_maybe_rollback(pid)(命中后触发自动回滚)。
"""
import ctypes
import logging
import os
import time
import zipfile

logger = logging.getLogger("PYAS.Canary")

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4

# 检测后缀:诱饵必须是文档类(在勒索目标清单里),其它类型没有诱饵意义
CANARY_NAMES = ("财务报表_2026.docx", "项目合同_存档.docx", "客户资料汇总.docx")

# 同一进程 60 秒内只告警一次(加密器会反复触碰同一批诱饵)
ALERT_COOLDOWN_SECONDS = 60.0
# 补种巡检间隔
ENSURE_INTERVAL_SECONDS = 3600.0

_CSIDL_DESKTOP = 0
_CSIDL_PERSONAL = 5


def _shell_folder(csidl: int) -> str:
    buf = ctypes.create_unicode_buffer(260)
    try:
        # SHGetFolderPathW 需要同时挂 user32/shell32;直接用 shell32 导出
        ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
        return buf.value or ""
    except Exception:
        return ""


def _canary_docx_bytes() -> bytes:
    """最小 OOXML 文档,内容即声明 —— 用户双击打开就能看到说明。"""
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>PYAS Security Cyanmod \u52d2\u7d22\u9632\u62a4\u8bf1\u9975\u6587\u4ef6</w:t></w:r></w:p>"
        "<w:p><w:r><w:t>\u8fd9\u662f\u6740\u6bd2\u8f6f\u4ef6\u6545\u610f\u653e\u7f6e\u7684\u8bf1\u9975\u6587\u4ef6\uff0c\u7528\u4e8e\u68c0\u6d4b\u52d2\u7d22\u884c\u4e3a\u3002"
        "\u8bf7\u52ff\u7f16\u8f91\u6216\u5220\u9664\uff1b\u5220\u9664\u540e\u4f1a\u81ea\u52a8\u6062\u590d\u3002"
        "\u5982\u9700\u5173\u95ed\u6b64\u529f\u80fd\uff0c\u8bf7\u5230\u9632\u62a4\u9875\u7684\u300c\u52d2\u7d22\u8bf1\u9975\u300d\u5f00\u5173\u3002</w:t></w:r></w:p>"
        "</w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        "</Relationships>"
    )
    buffer = io_bytes()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document)
    return buffer.getvalue()


def io_bytes():
    import io
    return io.BytesIO()


class CanaryMixin:
    """蜜罐文档的布点、检测与自愈;详见模块 docstring。"""

    def _canary_enabled(self) -> bool:
        try:
            with self.lock_config:
                return bool(self.pyas_config.get("canary_switch", True))
        except Exception:
            return True

    def _canary_dir_candidates(self) -> list:
        dirs = []
        desktop = _shell_folder(_CSIDL_DESKTOP)

        if desktop:
            dirs.append(desktop)

        personal = _shell_folder(_CSIDL_PERSONAL)

        if personal and personal != desktop:
            dirs.append(personal)

        user = str(getattr(self, "path_user", "") or "")

        if user and user not in dirs:
            dirs.append(user)

        return [d for d in dirs if os.path.isdir(d)]

    def canary_paths(self) -> dict:
        """{normcase 完整路径: (显示名, 布点目录)}。"""
        paths = {}

        if not self._canary_enabled():
            return paths

        payload = _canary_docx_bytes()

        for directory in self._canary_dir_candidates():
            for name in CANARY_NAMES:
                full = os.path.join(directory, name)
                paths[os.path.normcase(full)] = (full, payload)

        return paths

    def ensure_canaries(self) -> int:
        """补种缺失/被改名的诱饵并设置隐藏属性;返回补种数量。"""
        planted = 0

        if not self._canary_enabled():
            return planted

        try:
            for _key, (full, payload) in self.canary_paths().items():
                try:
                    if os.path.isfile(full):
                        continue

                    os.makedirs(os.path.dirname(full), exist_ok=True)

                    with open(full, "wb") as handle:
                        handle.write(payload)

                    ctypes.windll.kernel32.SetFileAttributesW(full, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
                    planted += 1
                except OSError:
                    logger.debug("canary plant failed: %s", full, exc_info=True)
        except Exception:
            logger.debug("canary ensure failed", exc_info=True)

        if planted:
            logger.info("canaries planted: %d", planted)

        return planted

    def _canary_on_write(self, pid: int, path: str) -> None:
        """ETW/文件监视的事件入口:命中蜜罐即高置信勒索告警。

        任何异常都在此消化 —— 本函数位于主事件链路上,绝不允许抛出。
        """
        try:
            if not self._canary_enabled():
                return

            key = os.path.normcase(path)
            canaries = getattr(self, "_canary_path_cache", None)

            if canaries is None or time.monotonic() - getattr(self, "_canary_cache_stamp", 0.0) > 30.0:
                canaries = self.canary_paths()
                self._canary_path_cache = canaries
                self._canary_cache_stamp = time.monotonic()

            if key not in canaries:
                return

            now = time.monotonic()

            if not hasattr(self, "_canary_alert_times"):
                self._canary_alert_times = {}

            last = self._canary_alert_times
            cooldown = ALERT_COOLDOWN_SECONDS

            if now - last.get(pid, 0.0) < cooldown:
                return

            last[pid] = now

            while len(last) > 256:
                last.pop(next(iter(last)))

            from PYAS_Behavior import BEHAVIOR_LOG_TEXTS  # noqa: 动作名/文案与行为防护同源

            name = ""
            try:
                name, _ = (self._etw_pid_info.get(pid) if getattr(self, "_etw_pid_info", None) else ("", ""))
            except Exception:
                pass

            suspect = name or f"PID {pid}"
            self.write_log(
                "WARN",
                "Canary Triggered",
                detail=self._loc(CANARY_LOG_TEXTS["triggered"]).format(suspect, path),
                pid=pid,
                source=path,
                success=False,
            )

            if getattr(self, "_last_notify_page", None) is not None or True:
                # 安全类通知:点击跳事件审计页(与勒索告警同一通道)
                self._last_notify_page = "audit_window"

            if getattr(self, "trigger_block_notification", None):
                try:
                    self.trigger_block_notification("block", path, path, pid)
                except Exception:
                    logger.debug("canary notification failed", exc_info=True)

            # 命中蜜罐 = 勒索几乎确定,触发与 L3 同款的自动回滚挂钩
            if getattr(self, "_behavior_maybe_rollback", None):
                self._behavior_maybe_rollback(pid)
        except Exception:
            logger.debug("canary check failed", exc_info=True)

    def canary_housekeeping(self) -> None:
        """后台巡检:周期补种(引擎初始化后由调度层拉起 daemon 循环)。"""
        while True:
            try:
                self.ensure_canaries()
            except Exception:
                logger.debug("canary housekeeping failed", exc_info=True)

            time.sleep(ENSURE_INTERVAL_SECONDS)


# 动作文与告警文案(动作名进 i18n.js 前端查词,构建守卫强制;详情写时本地化)
CANARY_ACTION = "Canary Triggered"

CANARY_LOG_TEXTS = {
    "triggered": {
        "traditional_switch": "{0} 觸碰了勒索防護誘餌文件,幾乎可以確認為勒索行為:{1}",
        "simplified_switch": "{0} 触碰了勒索防护诱饵文件,几乎可以确认为勒索行为:{1}",
        "english_switch": "{0} touched a ransomware canary file; this is near-certain ransomware behavior: {1}",
        "japanese_switch": "{0} がランサムウェア狩りのカナリアファイルに触れました。ほぼ確実にランサムウェアの挙動です: {1}",
        "korean_switch": "{0}이(가) 랜섬웨어 카나리아 파일을 건드렸습니다. 거의 확실한 랜섬웨어 행위입니다: {1}",
        "french_switch": "{0} a touché un fichier leurre anti-rançongiciel ; comportement quasi certain de rançongiciel : {1}",
        "spanish_switch": "{0} tocó un archivo señuelo anti-ransomware; comportamiento casi seguro de ransomware: {1}",
        "hindi_switch": "{0} ने रैंसमवेयर कैनरी फ़ाइल को छुआ; लगभग निश्चित रैंसमवेयर व्यवहार: {1}",
        "arabic_switch": "{0} لمس ملف طُعم لمكافحة الفدية؛ هذا سلوك شبه مؤكد لبرنامج الفدية: {1}",
        "russian_switch": "{0} затронул файл-приманку защиты от шифровальщиков; почти наверняка это вымогатель: {1}",
        "slovenian_switch": "{0} se je dotaknil vabila proti izsiljevalski programski opremi; to je skoraj gotovo izsiljevalsko vedenje: {1}",
    },
}
