from PYAS_Diagnostics import (
    log_exception,
    create_log_entry,
    is_ui_log_entry,
    MAX_LOG_ENTRIES,
)
import os
import time
import json
import uuid
import webview
from PYAS_Storage import atomic_write_json

from PYAS_LogTexts import LOG_TEXTS as _LT


class LogMixin:
    def load_logs(self):
        with self.lock_logs:
            pending_logs = list(self.logs_data)

            if os.path.exists(self.file_log):
                try:
                    with open(self.file_log, "r", encoding="utf-8") as f:
                        loaded_logs = json.load(f)

                    self.logs_data = (loaded_logs + pending_logs)[-MAX_LOG_ENTRIES:]
                except Exception:
                    log_exception("PYAS_Logs.LogMixin.load_logs:17")
                    self.logs_data = pending_logs

    def log_flush_thread(self):
        while not getattr(self, "closing", False):
            time.sleep(5)
            self.flush_logs_now()

    def write_log(
        self,
        level,
        action,
        detail=None,
        code=None,
        pid=None,
        file_hash=None,
        source=None,
        target=None,
        operate=None,
        success=True,
        ui_visible=None,
    ):
        entry = create_log_entry(
            level,
            action,
            detail,
            code,
            pid,
            file_hash,
            source,
            target,
            operate,
            success,
            ui_visible=ui_visible,
        )
        self._append_log_entry(entry)
        # 托盘 toast 不再随 BLOCK 日志自动触发:弹窗裁决的拦截用户刚刚亲眼
        # 确认过,重复通知会被误读为"绕过弹窗的自动拦截"。自动拦截的知情
        # 通知改由各自动拦截点显式调用 trigger_block_notification。

    def _append_log_entry(self, entry):
        with self.lock_logs:
            self.logs_data.append(entry)

            if len(self.logs_data) > MAX_LOG_ENTRIES:
                del self.logs_data[:-MAX_LOG_ENTRIES]

            self.logs_dirty = True

            if self._window and is_ui_log_entry(entry):
                js_cmd = f"if(window.updateLogs) window.updateLogs({json.dumps(entry)});"
                self.ui_queue.put(js_cmd)

    def get_logs(self, limit=300):
        with self.lock_logs:
            entries = [entry for entry in self.logs_data if is_ui_log_entry(entry)]
        # 跨桥序列化大列表会拖慢/失败,首页视图只需要最新部分
        return entries[-limit:] if limit else entries

    def clear_logs(self, log_ids=None):
        with self.lock_logs:
            if log_ids is None:
                self.logs_data = []
            else:
                self.logs_data = [log for log in self.logs_data if log["id"] not in log_ids]

            try:
                if not self.logs_data:
                    if os.path.exists(self.file_log):
                        os.remove(self.file_log)
                else:
                    atomic_write_json(self.file_log, self.logs_data)

            except Exception:
                log_exception("PYAS_Logs.LogMixin.clear_logs:73")
                self.logs_dirty = True
                return False

            self.logs_dirty = False
            return True

    def export_logs(self, log_ids=None):
        if self._window:
            path = self._window.create_file_dialog(
                webview.FileDialog.SAVE, directory="", save_filename="PYAS_Logs.json"
            )

            if path:
                target_path = path[0] if isinstance(path, (tuple, list)) else path

                with self.lock_logs:
                    export_data = [entry for entry in self.logs_data if is_ui_log_entry(entry)]

                    if log_ids is not None:
                        export_data = [log for log in export_data if log["id"] in log_ids]

                    try:
                        with open(target_path, "w", encoding="utf-8") as f:
                            json.dump(export_data, f, indent=4, ensure_ascii=False)

                        return True
                    except Exception:
                        log_exception("PYAS_Logs.LogMixin.export_logs:95")
                        pass

        return False

    def flush_logs_now(self):
        with self.lock_logs:
            if not getattr(self, "logs_dirty", False):
                return True

            try:
                atomic_write_json(self.file_log, self.logs_data)
                self.logs_dirty = False

                # 恢复通知只发一次:持续失败期间每 5 秒都会走到这里,不刷屏
                if getattr(self, "_flush_failing", False):
                    self._flush_failing = False
                    self.write_log(
                        "INFO",
                        "Log Write Failed",
                        detail=self._loc(_LT["log_flush_recovered"]),
                        ui_visible=True,
                    )
                return True
            except Exception as error:
                log_exception("PYAS_Logs.LogMixin.flush_logs_now:107")

                # 落盘失败必须让用户看见:Exception/WARN 类条目默认不进界面日志页,
                # 静默吞掉会让「日志不更新、审计丢失」看起来像功能坏了(2026-10-16
                # 的 ACL 事故:提权进程写下的 Report.json 让普通身份永远替换失败,
                # 全部日志积压在内存里,界面上却毫无征兆)。状态翻转时只报一次。
                if not getattr(self, "_flush_failing", False):
                    self._flush_failing = True
                    self.write_log(
                        "WARN",
                        "Log Write Failed",
                        detail=(
                            f"日志落盘失败,新条目暂存内存: {error}"
                        ),
                        success=False,
                        ui_visible=True,
                    )
                return False
