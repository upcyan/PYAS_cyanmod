"""行为防护:渐进监控 + 紧急卷影副本 + 行为回滚。

为什么这样设计
--------------
docs/behavior-defense.md 的边界在此同样成立:ETW 只知道「谁在何时动了哪个
文件」,不保存内容。用户态能做的内容留存是 VSS 卷影副本 —— 在进程改写行为
升级(同进程 10 秒窗口内改写多个文档类文件,但未到勒索阈值)时,抢在加密
蔓延之前对所在卷做一份快照;之后若该进程触发勒索告警,把快照里这些文件的
原样恢复回去,并把它新建的文件移入隔离目录。

分级(渐进):
  L1 关注  —— 记台账,不动作;
  L2 升级  —— 同进程窗口内 ≥L2_THRESHOLD 个不同文档类文件 → 紧急快照
              (每卷冷却 L2_SNAPSHOT_COOLDOWN 秒,避免频繁建卷);
  L3 告警  —— ≥L3_THRESHOLD(即 PYAS_ETW.BurstHeuristic 的勒索阈值)→
              既有托盘告警;若 behavior_auto_rollback 开启则自动回滚。

回滚的边界(诚实声明):
  - 只恢复快照之后被该进程改写/删除的文件;快照前已存在的加密无能为力。
  - ACL/ADS/硬链接等元数据不还原(见 behavior-defense.md),copy2 尽力保留
    时间戳与只读位。
  - 快照上下文 ClientAccessible 需要管理员 + VSS 服务;System Restore 被
    禁用的卷可能创建失败 —— 失败会记日志,告警链路不受影响。
  - 自动回滚默认关(behavior_auto_rollback):恢复操作本身有把合法批量写入
    (如网盘首次同步)打回旧版本的风险,必须显式开启。

结构
----
TouchedFilesLedger  每进程改写台账(回滚的依据),纯内存、有界。
VssSnapshotManager  卷影副本的创建/替换/查询(PowerShell Invoke-CimMethod,
                    JSON 落盘回传,与自启动 UAC 同一套模式);runner 可注入。
BehaviorMixin       宿主集成:写事件入口、L2 触发快照、L3 触发回滚。
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from collections import OrderedDict

logger = logging.getLogger("PYAS.Behavior")

from PYAS_ETW import BurstHeuristic

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

L2_THRESHOLD = 8
L2_WINDOW_SECONDS = 10.0
L2_SNAPSHOT_COOLDOWN_SECONDS = 600.0

ROLLBACK_TTL_SECONDS = 1800.0
LEDGER_MAX_PER_PID = 512
LEDGER_MAX_PIDS = 64
ROLLBACK_STAGING_DIRNAME = "BehaviorRollback"

# 动作名(i18n.js 有对应词条,契约测试强制)
ACTION_DEFENSE = "Behavior Defense"
ACTION_SNAPSHOT = "Behavior Snapshot"
ACTION_ROLLBACK = "Behavior Rollback"

BEHAVIOR_LOG_TEXTS = {
    "snapshot_deleted": {
        "traditional_switch": "已刪除卷影副本（{0}）",
        "simplified_switch": "已删除卷影副本（{0}）",
        "english_switch": "Shadow copy deleted ({0})",
        "japanese_switch": "シャドウコピーを削除しました（{0}）",
        "korean_switch": "섀도 복사본을 삭제했습니다({0})",
        "french_switch": "Copie instantanée supprimée ({0})",
        "spanish_switch": "Copia instantánea eliminada ({0})",
        "hindi_switch": "शैडो कॉपी हटाई गई ({0})",
        "arabic_switch": "تم حذف النسخة الظلية ({0})",
        "russian_switch": "Теневая копия удалена ({0})",
        "slovenian_switch": "Senčna kopija izbrisana ({0})",
    },
    "file_restored": {
        "traditional_switch": "已從卷影副本恢復： {0}",
        "simplified_switch": "已从卷影副本恢复： {0}",
        "english_switch": "Restored from shadow copy: {0}",
        "japanese_switch": "シャドウコピーから復元しました： {0}",
        "korean_switch": "섀도 복사본에서 복원했습니다: {0}",
        "french_switch": "Fichier restauré depuis la copie instantanée : {0}",
        "spanish_switch": "Archivo restaurado desde la copia instantánea: {0}",
        "hindi_switch": "शैडो कॉपी से पुनर्स्थापित: {0}",
        "arabic_switch": "تمت الاستعادة من النسخة الظلية: {0}",
        "russian_switch": "Восстановлено из теневой копии: {0}",
        "slovenian_switch": "Obnovljeno iz senčne kopije: {0}",
    },
    "snapshot_created": {
        "traditional_switch": "已建立緊急卷影副本（{0}），該進程改寫異常升級時可回滾",
        "simplified_switch": "已建立紧急卷影副本（{0}），该进程改写异常升级时可回滚",
        "english_switch": "Emergency shadow copy created on {0} for potential rollback",
        "japanese_switch": "緊急シャドウコピーを作成しました（{0}）。ロールバックに使用できます",
        "korean_switch": "긴급 섀도 복사본을 생성했습니다({0}). 롤백에 사용할 수 있습니다",
        "french_switch": "Copie instantanée d'urgence créée sur {0}, disponible pour restauration",
        "spanish_switch": "Copia instantánea de emergencia creada en {0}, disponible para revertir",
        "hindi_switch": "{0} पर आपातकालीन शैडो कॉपी बनाई गई, रोलबैक हेतु उपलब्ध",
        "arabic_switch": "تم إنشاء نسخة ظلية طارئة على {0}، متاحة للتراجع",
        "russian_switch": "Создана экстренная теневая копия на {0}, доступна для отката",
        "slovenian_switch": "Ustvarjena nujna senčna kopija na {0}, na voljo za vračanje",
    },
    "snapshot_failed": {
        "traditional_switch": "緊急卷影副本建立失敗： {0}",
        "simplified_switch": "紧急卷影副本创建失败： {0}",
        "english_switch": "Emergency shadow copy failed: {0}",
        "japanese_switch": "緊急シャドウコピーの作成に失敗: {0}",
        "korean_switch": "긴급 섀도 복사본 생성 실패: {0}",
        "french_switch": "Échec de la copie instantanée d'urgence : {0}",
        "spanish_switch": "Error en la copia instantánea de emergencia: {0}",
        "hindi_switch": "आपातकालीन शैडो कॉपी विफल: {0}",
        "arabic_switch": "فشلت النسخة الظلية الطارئة: {0}",
        "russian_switch": "Ошибка экстренной теневой копии: {0}",
        "slovenian_switch": "Nujna senčna kopija ni uspela: {0}",
    },
    "requires_etw": {
        "traditional_switch": "需要進程溯源（ETW）資料來源，行為防護未啟用",
        "simplified_switch": "需要进程溯源（ETW）数据源，行为防护未启用",
        "english_switch": "Behavior defense needs the attribution (ETW) source; not enabled",
        "japanese_switch": "プロセス追跡（ETW）のデータソースが必要のため、ビヘイビア防御は有効化できませんでした",
        "korean_switch": "프로세스 추적(ETW) 데이터 소스가 필요하여 행동 방어를 활성화하지 못했습니다",
        "french_switch": "La défense comportementale requiert la source de traçage (ETW) ; non activée",
        "spanish_switch": "La defensa conductual requiere la fuente de rastreo (ETW); no se activó",
        "hindi_switch": "व्यवहार रक्षा हेतु प्रक्रिया ट्रेसिंग (ETW) स्रोत आवश्यक; सक्षम नहीं हुई",
        "arabic_switch": "تحتاج الحماية السلوكية إلى مصدر التتبع (ETW)؛ لم تُفعّل",
        "russian_switch": "Поведенческой защите нужен источник трассировки (ETW); не включена",
        "slovenian_switch": "Vedenjska zaščita potrebuje vir sledenja (ETW); ni omogočena",
    },
    "etw_source_lost": {
        "traditional_switch": "資料來源（進程溯源）已關閉，行為防護暫停生效",
        "simplified_switch": "数据源（进程溯源）已关闭，行为防护暂停生效",
        "english_switch": "Behavior defense dormant: the attribution (ETW) source was turned off",
        "japanese_switch": "データソース（プロセス追跡）がオフのため、ビヘイビア防御は一時停止中です",
        "korean_switch": "데이터 소스(프로세스 추적)가 꺼져 행동 방어가 일시 중지되었습니다",
        "french_switch": "Défense comportementale en veille : la source de traçage (ETW) a été désactivée",
        "spanish_switch": "Defensa conductual en pausa: se desactivó la fuente de rastreo (ETW)",
        "hindi_switch": "व्यवहार रक्षा निष्क्रिय: प्रक्रिया ट्रेसिंग (ETW) स्रोत बंद कर दिया गया",
        "arabic_switch": "الحماية السلوكية موقوفة: أُغلق مصدر التتبع (ETW)",
        "russian_switch": "Поведенческая защита приостановлена: источник трассировки (ETW) отключён",
        "slovenian_switch": "Vedenjska zaščita v mirovanju: vir sledenja (ETW) je izklopljen",
    },
    "rollback_summary": {
        "traditional_switch": "已回滾 {0} 個檔案，隔離 {1} 個新檔案，跳過 {2} 個，失敗 {3} 個",
        "simplified_switch": "已回滚 {0} 个文件，隔离 {1} 个新文件，跳过 {2} 个，失败 {3} 个",
        "english_switch": "Restored {0} files, quarantined {1}, skipped {2}, failed {3}",
        "japanese_switch": "{0} 件をロールバック、{1} 件を隔離、{2} 件をスキップ、{3} 件失敗",
        "korean_switch": "{0}개 복원, {1}개 격리, {2}개 건너뜀, {3}개 실패",
        "french_switch": "{0} fichiers restaurés, {1} mis en quarantaine, {2} ignorés, {3} échecs",
        "spanish_switch": "{0} archivos restaurados, {1} en cuarentena, {2} omitidos, {3} fallos",
        "hindi_switch": "{0} फ़ाइलें पुनर्स्थापित, {1} संगरुध, {2} छोड़ी गईं, {3} विफल",
        "arabic_switch": "تمت استعادة {0} ملفًا، وعزل {1}، وتخطي {2}، وفشل {3}",
        "russian_switch": "Восстановлено {0}, изолировано {1}, пропущено {2}, ошибок {3}",
        "slovenian_switch": "Obnovljenih {0}, v karanteno {1}, preskočenih {2}, neuspešnih {3}",
    },
    "rollback_no_snapshot": {
        "traditional_switch": "沒有可用的緊急卷影副本，無法回滾",
        "simplified_switch": "没有可用的紧急卷影副本，无法回滚",
        "english_switch": "No emergency shadow copy available; rollback impossible",
        "japanese_switch": "利用可能な緊急シャドウコピーがなく、ロールバックできません",
        "korean_switch": "사용 가능한 긴급 섀도 복사본이 없어 롤백할 수 없습니다",
        "french_switch": "Aucune copie instantanée d'urgence disponible ; restauration impossible",
        "spanish_switch": "No hay copia instantánea de emergencia; no se puede revertir",
        "hindi_switch": "कोई आपातकालीन शैडो कॉपी उपलब्ध नहीं; रोलबैक असंभव",
        "arabic_switch": "لا توجد نسخة ظلية طارئة؛ التراجع مستحيل",
        "russian_switch": "Нет экстренной теневой копии; откат невозможен",
        "slovenian_switch": "Ni nujne senčne kopije; vračanje ni mogoče",
    },
}


def _now() -> float:
    return time.monotonic()


# ---------------------------------------------------------------------------
# 台账:每进程改写了哪些文件(回滚依据)
# ---------------------------------------------------------------------------


class TouchedFilesLedger:
    """按进程记录「何时改了哪个文件」,内存有界,过期即清。

    只存行为防护关心的文档类文件;回滚时按「快照建立之后」过滤。
    """

    def __init__(
        self,
        ttl_seconds: float = ROLLBACK_TTL_SECONDS,
        max_per_pid: int = LEDGER_MAX_PER_PID,
        max_pids: int = LEDGER_MAX_PIDS,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_per_pid = max_per_pid
        self._max_pids = max_pids
        self._lock = threading.Lock()
        # pid -> OrderedDict[path -> 最近一次改写时刻]
        self._entries: dict[int, OrderedDict[str, float]] = {}

    def record(self, pid: int, path: str, now: float | None = None) -> None:
        stamp = _now() if now is None else now

        with self._lock:
            paths = self._entries.get(pid)

            if paths is None:
                paths = OrderedDict()
                self._entries[pid] = paths

            paths[path] = stamp
            paths.move_to_end(path)

            while len(paths) > self._max_per_pid:
                paths.popitem(last=False)

            while len(self._entries) > self._max_pids:
                self._entries.pop(next(iter(self._entries)), None)

    def files_since(self, pid: int, since: float, drive: str, now: float | None = None) -> list[str]:
        """该进程在 since 之后改写、且位于指定盘符的去重路径(最近改写的靠后)。"""
        cutoff = _now() if now is None else now

        with self._lock:
            paths = self._entries.get(pid)

            if not paths:
                return []

            result = []

            for path, stamp in paths.items():
                if stamp < since or stamp > cutoff:
                    continue

                if not drive or not path.startswith(drive[:2]):
                    continue

                if path not in result:
                    result.append(path)

            return result

    def forget(self, pid: int) -> None:
        with self._lock:
            self._entries.pop(pid, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# ---------------------------------------------------------------------------
# VSS 卷影副本管理
# ---------------------------------------------------------------------------


class VssSnapshotManager:
    """每块卷最多保留一份「紧急快照」,新快照成功后再替换旧的。

    runner/now 可注入:测试时给假 runner(返回固定 JSON),不碰 PowerShell。
    """

    def __init__(self, state_path: str, runner=None, cooldown_seconds: float = L2_SNAPSHOT_COOLDOWN_SECONDS) -> None:
        self._state_path = state_path
        self._runner = runner or self._run_powershell
        self._cooldown = cooldown_seconds
        self._lock = threading.Lock()
        self.last_error = ""
        # drive("C:") -> {"id","device","created"(monotonic),"last_attempt"}
        self._snapshots: dict[str, dict] = {}
        self._load_state()

    # -- 公共接口 ----------------------------------------------------------

    def create_if_due(self, drive: str, now: float | None = None):
        """冷却期内直接返回现有快照;到期才真正建新的。

        返回 (状态, 设备路径):created=新建成功 / existing=冷却期复用 /
        cooldown=上次失败还在冷却 / failed=本次失败。设备仅在前两种非 None。
        冷却期与复用都不产生日志 —— 只有真实尝试才有资格写日志。
        """
        stamp = _now() if now is None else now
        drive = drive[:2].upper()

        with self._lock:
            existing = self._snapshots.get(drive)

            if existing and stamp - existing.get("last_attempt", 0.0) < self._cooldown:
                device = existing.get("device")

                if device:
                    return ("existing", device)

                return ("cooldown", None)

            self._snapshots.setdefault(drive, {})["last_attempt"] = stamp

        device = self._create(drive, stamp)

        with self._lock:
            if device:
                self._snapshots[drive]["created"] = stamp

        return (("created", device) if device else ("failed", None))

    def device_for(self, drive: str) -> str | None:
        with self._lock:
            entry = self._snapshots.get(drive[:2].upper())
            return entry.get("device") if entry else None

    def created_stamp(self, drive: str) -> float | None:
        with self._lock:
            entry = self._snapshots.get(drive[:2].upper())
            return entry.get("created") if entry else None

    def drives(self) -> list[tuple[str, str | None, float | None, float]]:
        """[(drive, device, created, created_wall), ...] — created 为 None 表示
        重启前的旧快照(不可用于回滚)。"""
        with self._lock:
            return [
                (drive, entry.get("device"), entry.get("created"), entry.get("created_wall", 0))
                for drive, entry in self._snapshots.items()
                if entry.get("device")
            ]

    def delete_snapshot(self, drive: str) -> bool:
        """删除指定卷的紧急快照(用户主动清理入口)。"""
        with self._lock:
            entry = self._snapshots.get(drive[:2].upper())
            shadow_id = entry.get("id") if entry else None

        if not shadow_id or not self._delete_by_id(shadow_id):
            return False

        with self._lock:
            self._snapshots.pop(drive[:2].upper(), None)

        self._save_state()
        return True

    @staticmethod
    def snapshot_path(device: str, dos_path: str) -> str:
        """C:\\a\\b.doc → <device>\\a\\b.doc(快照内同一路径)。"""
        rel = dos_path[2:].lstrip("\\") if len(dos_path) > 2 else dos_path.lstrip("\\")
        return device.rstrip("\\") + "\\" + rel

    # -- 快照创建:CIM 与 WMI v1 两条代码路径互为后备 ------------------------
    # 客户端 SKU 的 vssadmin 没有 create 命令(Server 专属,已实测「无效命令」)

    def _create(self, drive: str, stamp: float) -> str | None:
        """双路创建:CIM(Invoke-CimMethod)与 WMI v1(Get-WmiObject .Create)
        走不同的服务代码路径,一条失败时另一条仍可能成功。"""
        diagnostics = []

        for method in ("cim", "wmi"):
            if method == "cim":
                shadow_id, device, diagnostic = self._create_via_cim(drive)
            else:
                shadow_id, device, diagnostic = self._create_via_wmi(drive)

            if shadow_id and device:
                shadow_id = shadow_id.strip("{}")
                new_entry = {"id": shadow_id, "device": device, "last_attempt": stamp, "created_wall": time.time()}
                previous = None

                with self._lock:
                    previous = self._snapshots.get(drive)
                    self._snapshots[drive] = {**previous, **new_entry} if previous else dict(new_entry)

                # 旧的快照在新快照就位后删除,失败不影响新快照可用性
                if previous and previous.get("id") and previous["id"] != shadow_id:
                    self._delete_by_id(previous["id"])

                self._save_state()
                self.last_error = ""
                return device

            diagnostics.append(f"{method}: {diagnostic}")

        self.last_error = "; ".join(diagnostics)
        logger.warning("VSS snapshot failed: %s", self.last_error)
        return None

    def _create_via_wmi(self, drive: str):
        """WMI v1 路径(Get-WmiObject .Create);返回 (id, device, 诊断)。"""
        result_file = os.path.join(
            os.path.dirname(self._state_path), f"pyas_vss_{uuid.uuid4().hex}.json"
        )
        script = (
            "$ErrorActionPreference='Stop';"
            "$p='" + result_file.replace("'", "''") + "';"
            "try{"
            "$r=(Get-WmiObject -List Win32_ShadowCopy).Create('" + drive + "\\', 'ClientAccessible');"
            "if($r.ReturnValue -ne 0){throw ('return='+$r.ReturnValue)}"
            "$g='$($r.ShadowID)'.Replace('{','').Replace('}','');"
            "$sc=Get-WmiObject Win32_ShadowCopy -Filter \"ID='$g'\";"
            "if(-not $sc){$sc=Get-WmiObject Win32_ShadowCopy -Filter \"ID='{$g}'\"};"
            "if(-not $sc){$sc=Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID.Replace('{','').Replace('}','') -eq $g}};"
            "if(-not $sc){throw 'device query failed'}"
            "@{id=$r.ShadowID;device=$sc.DeviceName}|ConvertTo-Json -Compress|Set-Content -LiteralPath $p -Encoding UTF8"
            "}catch{$_.Exception.Message|Set-Content -LiteralPath $p -Encoding UTF8;exit 1}"
        )

        try:
            ok, payload, error_text = self._run_result_script(script, result_file)

            if ok and payload.get("id") and payload.get("device"):
                return (str(payload["id"]), str(payload["device"]), "")

            # 诊断带实际字段与原始内容:远程一次运行即可分辨失败形态
            diag = ("; ".join(f"{k}={v}" for k, v in payload.items())
                    or error_text
                    or ("powershell exited nonzero" if not ok else "result file not written"))
            return (None, None, diag)
        finally:
            try:
                if os.path.exists(result_file):
                    os.remove(result_file)
            except OSError:
                pass

    def _create_via_cim(self, drive: str):
        """CIM/PowerShell 后备路径;返回 (id, device, 诊断)。"""
        result_file = os.path.join(
            os.path.dirname(self._state_path), f"pyas_vss_{uuid.uuid4().hex}.json"
        )
        volume = drive + "\\"
        script = (
            "$ErrorActionPreference='Stop';"
            "$p='" + result_file.replace("'", "''") + "';"
            "try{"
            "$r=Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create "
            "-Arguments @{Volume='" + volume + "';Context='ClientAccessible'};"
            "if($r.ReturnValue -ne 0){throw ('return='+$r.ReturnValue)}"
            "$g='$($r.ShadowID)'.Replace('{','').Replace('}','');"
            "$sc=Get-CimInstance Win32_ShadowCopy -Filter \"ID='$g'\";"
            "if(-not $sc){$sc=Get-CimInstance Win32_ShadowCopy -Filter \"ID='{$g}'\"};"
            "if(-not $sc){$sc=Get-CimInstance Win32_ShadowCopy | Where-Object {$_.ID.Replace('{','').Replace('}','') -eq $g}};"
            "if(-not $sc){throw 'device query failed'}"
            "@{id=$r.ShadowID;device=$sc.DeviceName}|ConvertTo-Json -Compress|Set-Content -LiteralPath $p -Encoding UTF8"
            "}catch{$_.Exception.Message|Set-Content -LiteralPath $p -Encoding UTF8;exit 1}"
        )

        try:
            ok, _output = self._runner(script, result_file)
            payload, error_text = {}, ""

            if os.path.exists(result_file):
                with open(result_file, "r", encoding="utf-8-sig") as f:
                    content = f.read().strip()

                try:
                    loaded = json.loads(content)

                    if isinstance(loaded, dict):
                        payload = loaded
                    else:
                        error_text = str(loaded)[:200]
                except ValueError:
                    # PowerShell catch 分支写入的是纯文本错误
                    error_text = content[:200]
            else:
                error_text = "result file not written"

            if payload.get("id") and payload.get("device"):
                return (str(payload["id"]), str(payload["device"]), "")

            # 诊断带原始内容:id/device 缺失时(如 Win11 24H2+ 对 WMI 创建
            # 的限制),远程日志可直接分辨是拒绝、空值还是其他形态
            return (None, None, error_text
                    or ("powershell exited nonzero" if not ok else "no id/device returned"))
        finally:
            try:
                if os.path.exists(result_file):
                    os.remove(result_file)
            except OSError:
                pass

    def _delete_by_id(self, shadow_id: str) -> bool:
        # vssadmin 首选(/quiet 免确认);失败退回 CIM
        try:
            completed = subprocess.run(
                ["vssadmin", "delete", "shadows", f"/shadow={shadow_id}", "/quiet"],
                capture_output=True,
                timeout=120,
                text=True,
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

            if completed.returncode == 0:
                return True
        except Exception:
            logger.debug("vssadmin delete failed", exc_info=True)

        script = (
            "try{Get-CimInstance Win32_ShadowCopy -Filter \"ID='" + shadow_id + "'\"|"
            "Remove-CimInstance;exit 0}catch{exit 1}"
        )
        ok, _ = self._runner(script, None)
        return ok

    def _run_result_script(self, script: str, result_file: str):
        """编码运行 PowerShell 脚本并解析其写出的 JSON 结果文件。
        返回 (ok, payload, error_text)。"""
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-EncodedCommand",
                 base64.b64encode(script.encode("utf-16-le")).decode("ascii")],
                capture_output=True,
                timeout=120,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as error:
            return (False, {}, f"spawn failed: {error}")

        ok = completed.returncode == 0
        payload, error_text = {}, ""

        if os.path.exists(result_file):
            with open(result_file, "r", encoding="utf-8-sig") as stream:
                content = stream.read().strip()

            try:
                loaded = json.loads(content)

                if isinstance(loaded, dict):
                    payload = loaded
                else:
                    error_text = str(loaded)[:200]
            except ValueError:
                # catch 分支写入的是纯文本错误
                error_text = content[:200]

        if payload.get("id") and payload.get("device"):
            return (True, payload, "")

        # 诊断带实际字段:远端一次运行即可分辨是拒绝、空值还是字段缺失
        diag = "; ".join(f"{k}={v}" for k, v in payload.items()) or error_text
        return (False, payload, diag
                or ("powershell exited nonzero" if not ok else "result file not written"))

    @staticmethod
    def _run_powershell(script: str, result_file: str | None):
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        command = [
            "powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded
        ]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                timeout=90,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as error:
            return (False, str(error))

        return (completed.returncode == 0, completed.stdout.decode("utf-8", "ignore"))

    # -- 状态持久化(重启后还能替换/清理自己建的快照) -----------------------

    def _load_state(self):
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                stored = json.load(f)

            if isinstance(stored, dict):
                for drive, entry in stored.items():
                    if isinstance(entry, dict) and entry.get("id") and entry.get("device"):
                        # 重启后 monotonic 基准失效:created 置空 → 回滚不可用,
                        # 但设备仍可被下次 L2 替换
                        self._snapshots[drive] = {**entry, "created": None, "last_attempt": 0.0}
        except (OSError, ValueError):
            pass

    def _save_state(self):
        payload = {
            drive: {"id": entry.get("id"), "device": entry.get("device")}
            for drive, entry in self._snapshots.items()
            if entry.get("id")
        }

        try:
            os.makedirs(os.path.dirname(self._state_path), exist_ok=True)

            with open(self._state_path, "w", encoding="utf-8") as f:
                json.dump(payload, f)
        except OSError:
            logger.debug("vss state save failed", exc_info=True)


# ---------------------------------------------------------------------------
# 宿主集成
# ---------------------------------------------------------------------------


class BehaviorMixin:
    """behavior_defense_switch 的执行体。

    依赖宿主提供:lock_config/pyas_config/write_log/_loc/path_config/
    is_in_whitelist,以及 PYAS_ETW.EtwMixin 在写事件里调用本混入的入口。
    """

    # -- 配置读取(5 秒缓存,热路径不抢 config 锁) ---------------------------

    def _behavior_switch_cached(self) -> bool:
        now = _now()

        if now - getattr(self, "_behavior_switch_stamp", 0.0) > 5.0:
            with self.lock_config:
                self._behavior_switch_value = bool(
                    self.pyas_config.get("behavior_defense_switch", False)
                )
            self._behavior_switch_stamp = now

        return getattr(self, "_behavior_switch_value", False)

    def _behavior_auto_rollback_cached(self) -> bool:
        now = _now()

        if now - getattr(self, "_behavior_auto_stamp", 0.0) > 5.0:
            with self.lock_config:
                self._behavior_auto_value = bool(
                    self.pyas_config.get("behavior_auto_rollback", False)
                )
            self._behavior_auto_stamp = now

        return getattr(self, "_behavior_auto_value", False)

    # -- 写事件入口(EtwMixin._on_etw_write 调用,已在监控后缀闸门之后) ------

    def _spawn_behavior_worker(self, target, name: str) -> None:
        """慢操作(PowerShell 快照/逐文件回滚)的后台派发;测试宿主覆盖为内联。"""
        threading.Thread(target=target, name=name, daemon=True).start()

    def _behavior_on_write(self, pid: int, path: str, now: float | None = None) -> None:
        """写/删事件统一入口:开关关闭直接返回,内部只记文档类目标。

        系统目录与白名单文件不参与:前者是系统自身高频改写(aidd 缓冲等),
        后者是管理员明确信任的对象,计入只会制造勒索误报。"""
        if not self._behavior_switch_cached():
            return

        stamp = _now() if now is None else now

        if not BurstHeuristic.is_target(path):
            return

        system_root = str(getattr(self, "path_system", "") or "C:\\Windows")

        if path.lower().startswith(system_root.lower()) or self.is_in_whitelist(path):
            return

        self._behavior_ledger.record(pid, path, stamp)

        escalation = self._behavior_l2.record(pid, path, stamp)

        if escalation:
            self._behavior_escalate(pid, path, stamp)

    def _behavior_escalate(self, pid: int, path: str, stamp: float) -> None:
        """L2:抢在加密蔓延前留存快照;失败只记日志,不影响告警链路。

        PowerShell 建快照可达数十秒,绝不能在 ETW 回调线程里同步执行 ——
        事件消费被堵住会撑爆内核缓冲。派后台线程,冷却由 create_if_due 把关。
        """
        self._ensure_vss_manager()
        drive = path[:2].upper()

        def worker():
            state, device = self._vss.create_if_due(drive)

            if state in ("existing", "cooldown"):
                # 冷却期内复用/上次失败未到期:不重复记日志
                return

            if state == "created":
                self.write_log(
                    "INFO",
                    ACTION_SNAPSHOT,
                    detail=self._loc(BEHAVIOR_LOG_TEXTS["snapshot_created"]).format(drive),
                    pid=pid,
                )
            else:
                self.write_log(
                    "WARN",
                    ACTION_SNAPSHOT,
                    detail=self._loc(BEHAVIOR_LOG_TEXTS["snapshot_failed"]).format(
                        getattr(self._vss, "last_error", "") or "unknown"
                    ),
                    pid=pid,
                    success=False,
                )

        self._spawn_behavior_worker(worker, "PYAS-Behavior-Snapshot")

    def _ensure_vss_manager(self) -> None:
        if getattr(self, "_vss", None) is None:
            data_dir = os.path.join(self.path_config, "PYAS")
            self._vss = VssSnapshotManager(
                state_path=os.path.join(data_dir, "vss_snapshots.json")
            )

    # -- L3 勒索告警挂钩(EtwMixin._etw_burst_alert 调用) --------------------

    def _behavior_maybe_rollback(self, pid: int) -> None:
        if not self._behavior_switch_cached() or not self._behavior_auto_rollback_cached():
            return

        # 回滚是逐文件 I/O,同样不能堵 ETW 回调线程;台账加锁并发安全
        self._spawn_behavior_worker(
            lambda: self.rollback_process_writes(pid), "PYAS-Behavior-Rollback"
        )

    def rollback_process_writes(self, pid: int, now: float | None = None) -> dict:
        """把该进程在快照之后改写的文件恢复为快照版本,新文件移入隔离目录。"""
        stamp = _now() if now is None else now
        summary = {"restored": 0, "quarantined": 0, "skipped": 0, "failed": 0}

        drives = self._snapshot_drives()

        if not drives:
            self.write_log(
                "WARN",
                ACTION_ROLLBACK,
                detail=self._loc(BEHAVIOR_LOG_TEXTS["rollback_no_snapshot"]),
                pid=pid,
                success=False,
            )
            return summary

        for drive, device, created in drives:
            if created is None:
                continue  # 重启加载的旧快照:没有可靠的时间基准,不回滚

            paths = self._behavior_ledger.files_since(pid, created, drive, stamp)

            for path in paths:
                self._rollback_one(path, device, drive, summary)

        self.write_log(
            "WARN",
            ACTION_ROLLBACK,
            detail=self._loc(BEHAVIOR_LOG_TEXTS["rollback_summary"]).format(
                summary["restored"], summary["quarantined"], summary["skipped"], summary["failed"]
            ),
            pid=pid,
            success=summary["failed"] == 0,
        )
        self._behavior_ledger.forget(pid)
        return summary

    def _snapshot_drives(self):
        self._ensure_vss_manager()
        return self._vss.drives()

    def _rollback_one(self, path: str, device: str, drive: str, summary: dict) -> None:
        # 白名单文件绝不回滚:管理员明确信任的对象不因启发式而改写
        try:
            if self.is_in_whitelist(path):
                summary["skipped"] += 1
                return
        except Exception:
            logger.debug("whitelist check failed for %s", path, exc_info=True)

        source = VssSnapshotManager.snapshot_path(device, path)

        try:
            if os.path.isfile(source):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                shutil.copy2(source, path)
                summary["restored"] += 1
            elif os.path.isfile(path):
                # 快照里没有 = 该进程新建的文件,移入隔离目录而不是删除
                staging = os.path.join(
                    self.path_config, "PYAS", ROLLBACK_STAGING_DIRNAME, str(int(time.time()))
                )
                os.makedirs(staging, exist_ok=True)
                destination = os.path.join(staging, os.path.basename(path))
                counter = 1

                while os.path.exists(destination):
                    stem, ext = os.path.splitext(os.path.basename(path))
                    destination = os.path.join(staging, f"{stem}_{counter}{ext}")
                    counter += 1

                shutil.move(path, destination)
                summary["quarantined"] += 1
            else:
                summary["skipped"] += 1
        except OSError as error:
            summary["failed"] += 1
            logger.warning("rollback failed for %s: %s", path, error)
